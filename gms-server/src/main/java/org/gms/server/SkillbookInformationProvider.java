/*
    This file is part of the HeavenMS MapleStory Server
    Copyleft (L) 2016 - 2019 RonanLana

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.server;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.gms.client.Character;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ReactordropsDO;
import org.gms.dao.mapper.ReactordropsMapper;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.util.SpringContextUtil;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 技能书信息提供者
 * <p>
 * 仅用于一个脚本，为玩家提供关于技能书来源的信息。
 *
 * @author RonanLana
 */
@Slf4j
public class SkillbookInformationProvider {
    // 使用 ConcurrentHashMap 实现线程安全的懒加载缓存
    private static final Map<Integer, SkillBookEntry> foundSkillbooks = new ConcurrentHashMap<>();
    private static volatile boolean loaded = false; // 懒加载状态标记

    public enum SkillBookEntry {
        UNAVAILABLE,
        QUEST,
        QUEST_BOOK,
        QUEST_REWARD,
        REACTOR,
        SCRIPT
    }

    private static final int SKILLBOOK_MIN_ITEMID = 2280000;
    private static final int SKILLBOOK_MAX_ITEMID = 2300000;  // 不包含

    /**
     * 全量加载所有技能书的来源信息。
     * 用于预加载模式。
     */
    public static void loadAllSkillbookInformation() {
        if (loaded) {
            return;
        }
        long startTime = System.currentTimeMillis();
        synchronized (SkillbookInformationProvider.class) {
            if (loaded) {
                return;
            }
            Map<Integer, SkillBookEntry> loadedData = new HashMap<>();
            loadedData.putAll(fetchSkillbooksFromQuests());
            loadedData.putAll(fetchSkillbooksFromReactors());
            loadedData.putAll(fetchSkillbooksFromScripts());
            foundSkillbooks.putAll(loadedData);
            loaded = true;
            log.info("技能书来源信息加载完成，总共 {} 条记录，耗时：{} 秒毫", foundSkillbooks.size(), System.currentTimeMillis() - startTime);
        }
    }

    /**
     * 懒加载所有技能书的来源信息。
     * 使用双重检查锁定模式确保只加载一次。
     */
    private static void lazyLoad() {
        if (!loaded) {
            loadAllSkillbookInformation(); // 懒加载本质上就是第一次访问时进行全量加载
        }
    }

    private static boolean is4thJobSkill(int itemid) {
        return itemid / 10000 % 10 == 2;
    }

    private static boolean isSkillBook(int itemid) {
        return itemid >= SKILLBOOK_MIN_ITEMID && itemid < SKILLBOOK_MAX_ITEMID;
    }

    private static boolean isQuestBook(int itemid) {
        return itemid >= 4001107 && itemid <= 4001114 || itemid >= 4161015 && itemid <= 4161023;
    }

    private static int fetchQuestbook(Data checkData, String quest) {
        Data questStartData = checkData.getChildByPath(quest).getChildByPath("0");

        Data startReqItemData = questStartData.getChildByPath("item");
        if (startReqItemData != null) {
            for (Data itemData : startReqItemData.getChildren()) {
                int itemId = DataTool.getInt("id", itemData, 0);
                if (isQuestBook(itemId)) {
                    return itemId;
                }
            }
        }

        Data startReqQuestData = questStartData.getChildByPath("quest");
        if (startReqQuestData != null) {
            Set<Integer> reqQuests = new HashSet<>();

            for (Data questStatusData : startReqQuestData.getChildren()) {
                int reqQuest = DataTool.getInt("id", questStatusData, 0);
                if (reqQuest > 0) {
                    reqQuests.add(reqQuest);
                }
            }

            for (Integer reqQuest : reqQuests) {
                int book = fetchQuestbook(checkData, Integer.toString(reqQuest));
                if (book > -1) {
                    return book;
                }
            }
        }

        return -1;
    }

    private static Map<Integer, SkillBookEntry> fetchSkillbooksFromQuests() {
        DataProvider questDataProvider = DataProviderFactory.getDataProvider(WZFiles.QUEST);
        Data actData = questDataProvider.getData("Act.img");
        Data checkData = questDataProvider.getData("Check.img");

        final Map<Integer, SkillBookEntry> loadedSkillbooks = new HashMap<>();
        if (actData == null || checkData == null) {
            log.error("无法从 Quest.wz 中加载 Act.img 或 Check.img，从任务中获取技能书来源失败。");
            return loadedSkillbooks;
        }

        for (Data questData : actData.getChildren()) {
            for (Data questStatusData : questData.getChildren()) {
                for (Data questNodeData : questStatusData.getChildren()) {
                    String actNodeName = questNodeData.getName();
                    if (actNodeName.contentEquals("item")) {
                        for (Data questItemData : questNodeData.getChildren()) {
                            int itemId = DataTool.getInt("id", questItemData, 0);
                            int itemCount = DataTool.getInt("count", questItemData, 0);

                            if (isSkillBook(itemId) && itemCount > 0) {
                                int questbook = fetchQuestbook(checkData, questData.getName());
                                if (questbook < 0) {
                                    loadedSkillbooks.put(itemId, SkillBookEntry.QUEST);
                                } else {
                                    loadedSkillbooks.put(itemId, SkillBookEntry.QUEST_BOOK);
                                }
                            }
                        }
                    } else if (actNodeName.contentEquals("skill")) {
                        for (Data questSkillData : questNodeData.getChildren()) {
                            int skillId = DataTool.getInt("id", questSkillData, 0);
                            if (is4thJobSkill(skillId)) {
                                // 负的 itemid 是技能奖励
                                int questbook = fetchQuestbook(checkData, questData.getName());
                                if (questbook < 0) {
                                    loadedSkillbooks.put(-skillId, SkillBookEntry.QUEST_REWARD);
                                } else {
                                    loadedSkillbooks.put(-skillId, SkillBookEntry.QUEST_BOOK);
                                }
                            }
                        }
                    }
                }
            }
        }

        return loadedSkillbooks;
    }

    private static Map<Integer, SkillBookEntry> fetchSkillbooksFromReactors() {
        Map<Integer, SkillBookEntry> loadedSkillbooks = new HashMap<>();
        try {
            ReactordropsMapper mapper = SpringContextUtil.getBean(ReactordropsMapper.class);
            QueryWrapper query = QueryWrapper.create()
                    .select(ReactordropsDO::getItemid)
                    .where(ReactordropsDO::getItemid).ge(SKILLBOOK_MIN_ITEMID)
                    .and(ReactordropsDO::getItemid).lt(SKILLBOOK_MAX_ITEMID);

            List<ReactordropsDO> results = mapper.selectListByQuery(query);
            for (ReactordropsDO result : results) {
                loadedSkillbooks.put(result.getItemid(), SkillBookEntry.REACTOR);
            }
        } catch (Exception e) {
            log.error("从数据库加载反应堆掉落的技能书信息失败。", e);
        }
        return loadedSkillbooks;
    }

    private static void listFiles(String directoryName, ArrayList<Path> files) {
        Path directory = Path.of(directoryName);
        if (!Files.exists(directory)) return;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
            for (Path path : stream) {
                if (Files.isRegularFile(path)) {
                    files.add(path);
                } else if (Files.isDirectory(path)) {
                    listFiles(path.toAbsolutePath().toString(), files);
                }
            }
        } catch (IOException e) {
            log.error("读取目录时发生IO异常", e);
        }
    }

    private static List<Path> listFilesFromDirectoryRecursively(String directory) {
        ArrayList<Path> files = new ArrayList<>();
        listFiles(directory, files);
        return files;
    }

    private static Set<Integer> findMatchingSkillbookIdsOnFile(String fileContent) {
        Set<Integer> skillbookIds = new HashSet<>(4);
        Matcher searchM = Pattern.compile("22(8|9)[0-9]{4}").matcher(fileContent);
        int idx = 0;
        while (searchM.find(idx)) {
            idx = searchM.end();
            skillbookIds.add(Integer.valueOf(fileContent.substring(searchM.start(), idx)));
        }
        return skillbookIds;
    }

    private static String readFileToString(Path file, String encoding) throws IOException {
        return Files.readString(file);
    }

    private static Map<Integer, SkillBookEntry> fileSearchMatchingData(Path file) {
        Map<Integer, SkillBookEntry> scriptFileSkillbooks = new HashMap<>();
        try {
            String fileContent = readFileToString(file, "UTF-8");
            Set<Integer> skillbookIds = findMatchingSkillbookIdsOnFile(fileContent);
            for (Integer skillbookId : skillbookIds) {
                scriptFileSkillbooks.put(skillbookId, SkillBookEntry.SCRIPT);
            }
        } catch (IOException ioe) {
            log.error("读取文件失败:{}", file.getFileName(), ioe);
        }
        return scriptFileSkillbooks;
    }

    private static Map<Integer, SkillBookEntry> fetchSkillbooksFromScripts() {
        Map<Integer, SkillBookEntry> scriptSkillbooks = new HashMap<>();
        for (Path file : listFilesFromDirectoryRecursively("./scripts")) {
            if (file.getFileName().toString().endsWith(".js")) {
                scriptSkillbooks.putAll(fileSearchMatchingData(file));
            }
        }
        return scriptSkillbooks;
    }

    public static SkillBookEntry getSkillbookAvailability(int itemId) {
        lazyLoad(); // 确保数据已加载
        return foundSkillbooks.getOrDefault(itemId, SkillBookEntry.UNAVAILABLE);
    }

    public static List<Integer> getTeachableSkills(Character chr) {
        lazyLoad(); // 确保数据已加载
        List<Integer> list = new ArrayList<>();
        for (Integer book : foundSkillbooks.keySet()) {
            if (book >= 0) {
                continue;
            }
            int skillid = -book;
            if (skillid / 10000 == chr.getJob().getId()) {
                if (chr.getMasterLevel(skillid) == 0) {
                    list.add(-skillid);
                }
            }
        }
        return list;
    }
}
