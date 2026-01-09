package org.gms.server;

import com.mybatisflex.core.paginate.Page;
import org.gms.constants.api.InformationType;
import org.gms.exception.BizException;
import org.gms.model.pojo.InformationSearch;
import org.gms.model.pojo.InformationResult;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.util.I18nUtil;
import org.gms.util.RequireUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class CommonInformation {
    private static CommonInformation instance;
    private final DataProvider stringData;
    private List<InformationResult> cachedMaps;

    private CommonInformation() {
        stringData = DataProviderFactory.getDataProvider(WZFiles.STRING);
    }

    public static CommonInformation getInstance() {
        if (instance == null) {
            instance = new CommonInformation();
        }
        return instance;
    }

    /**
     * 获取所有地图信息，带缓存
     */
    public List<InformationResult> getAllMaps() {
        if (cachedMaps != null) {
            return cachedMaps;
        }
        synchronized (this) {
            if (cachedMaps != null) {
                return cachedMaps;
            }
            List<InformationResult> results = new ArrayList<>();
            Data data = stringData.getData("Map.img");
            if (data != null) {
                for (Data child : data.getChildren()) {
                    for (Data map : child.getChildren()) {
                        String id = map.getName();
                        // 过滤非数字ID的节点
                        if (!id.matches("\\d+")) {
                            continue;
                        }
                        String name = DataTool.getString("mapName", map, "");
                        String desc = DataTool.getString("streetName", map, "");
                        results.add(InformationResult.builder()
                                .type(InformationType.MAP.getType())
                                .id(Integer.parseInt(id))
                                .name(name)
                                .desc(desc)
                                .build());
                    }
                }
            }
            cachedMaps = results;
            return cachedMaps;
        }
    }

    public List<String> getStreetNames() {
        return getAllMaps().stream()
                .map(InformationResult::getDesc)
                .filter(RequireUtil::isNotEmpty)
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    public List<InformationResult> getMapsByStreetName(String streetName) {
        return getAllMaps().stream()
                .filter(map -> streetName.equals(map.getDesc()))
                .collect(Collectors.toList());
    }

    /**
     * 硬查xml
     * 因为支持模糊匹配，所以无法使用lru缓存，否则可能导致查出的数据不完整
     */
    public Page<InformationResult> getStringInformation(InformationSearch condition) {
        RequireUtil.requireNotEmpty(condition.getTypes(), I18nUtil.getExceptionMessage("PARAMETER_SHOULD_NOT_EMPTY", "types"));
        List<InformationResult> results = new ArrayList<>();
        long total = 0;
        for (String type : condition.getTypes()) {
            InformationType infType = InformationType.ofType(type);
            if (infType == null) {
                throw new BizException(I18nUtil.getExceptionMessage("UNSUPPORTED_TYPE"));
            }
            total += searchXML(results, infType, condition.getFilter(), condition.getFilterType(), condition.isFullMatch(), condition.getPage(), condition.getPageSize(), condition.getGender(), condition.getColor());
        }
        
        // 构造分页对象
        Page<InformationResult> page = new Page<>();
        page.setRecords(results);
        page.setTotalRow(total);
        if (condition.getPage() != null) {
            page.setPageNumber(condition.getPage());
        }
        if (condition.getPageSize() != null) {
            page.setPageSize(condition.getPageSize());
        }
        
        return page;
    }

    private long searchXML(List<InformationResult> results, InformationType infType, String filter, int filterType, boolean fullMatch, Integer page, Integer pageSize, Integer gender, Integer color) {
        Data data;
        long count = 0;
        switch (infType) {
            case CASH -> {
                data = stringData.getData("Cash.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case CONSUME -> {
                data = stringData.getData("Consume.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case EQP -> {
                data = stringData.getData("Eqp.img").getChildByPath("Eqp");
                for (Data child : data.getChildren()) {
                    count += addResult(results, infType, child, filter, filterType, fullMatch, page, pageSize, gender, color);
                }
            }
            case ETC -> {
                data = stringData.getData("Etc.img").getChildByPath("Etc");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case INS -> {
                data = stringData.getData("Ins.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case MAP -> {
                data = stringData.getData("Map.img");
                for (Data child : data.getChildren()) {
                    count += addMapResult(results, infType, child, filter, filterType, fullMatch, page, pageSize);
                }
            }
            case MOB -> {
                data = stringData.getData("Mob.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case NPC -> {
                data = stringData.getData("Npc.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case PET -> {
                data = stringData.getData("Pet.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case SKILL -> {
                data = stringData.getData("Skill.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case HAIR -> {
                data = stringData.getData("Eqp.img").getChildByPath("Eqp/Hair");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
            case FACE -> {
                data = stringData.getData("Eqp.img").getChildByPath("Eqp/Face");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color);
            }
        }
        return count;
    }

    private long addResult(List<InformationResult> results, InformationType infType, Data data, String filter, int filterType, boolean fullMatch, Integer page, Integer pageSize, Integer gender, Integer color) {
        RequireUtil.requireNotNull(data, I18nUtil.getExceptionMessage("MISSING_RESOURCE", infType.getType()));
        
        int start = 0;
        int end = Integer.MAX_VALUE;
        if (page != null && pageSize != null) {
            start = (page - 1) * pageSize;
            end = start + pageSize;
        }
        
        long matchCount = 0;
        
        for (Data child : data.getChildren()) {
            String id = child.getName();
            String name = DataTool.getString("name", child, "");
            String desc = DataTool.getString("desc", child, "");
            
            // 检查性别和颜色
            if (!checkHairFaceLogic(infType, id, gender, color)) {
                continue;
            }

            if (isMatch(id, name, desc, filter, filterType, fullMatch)) {
                if (matchCount >= start && matchCount < end) {
                    results.add(InformationResult.builder()
                            .type(infType.getType())
                            .id(Integer.parseInt(id))
                            .name(name)
                            .desc(desc)
                            .build());
                }
                matchCount++;
            }
        }
        return matchCount;
    }

    private long addMapResult(List<InformationResult> results, InformationType infType, Data data, String filter, int filterType, boolean fullMatch, Integer page, Integer pageSize) {
        RequireUtil.requireNotNull(data, I18nUtil.getExceptionMessage("MISSING_RESOURCE", infType.getType()));
        
        int start = 0;
        int end = Integer.MAX_VALUE;
        if (page != null && pageSize != null) {
            start = (page - 1) * pageSize;
            end = start + pageSize;
        }
        
        long matchCount = 0;
        
        for (Data child : data.getChildren()) {
            String id = child.getName();
            String name = DataTool.getString("mapName", child, "");
            String desc = DataTool.getString("streetName", child, "");
            if (isMatch(id, name, desc, filter, filterType, fullMatch)) {
                if (matchCount >= start && matchCount < end) {
                    results.add(InformationResult.builder()
                            .type(infType.getType())
                            .id(Integer.parseInt(id))
                            .name(name)
                            .desc(desc)
                            .build());
                }
                matchCount++;
            }
        }
        return matchCount;
    }

    /**
     * 模糊搜索，支持id,name,desc内容搜索
     * @param id
     * @param name
     * @param desc
     * @param filter
     * @param filterType
     * @param fullMatch
     * @return
     */
    private boolean isMatch(String id, String name, String desc, String filter, int filterType, boolean fullMatch) {
        // 如果 filter 为空或 %，则匹配所有
        if (filter == null || filter.isEmpty() || "%".equals(filter)) {
            return true;
        }

        boolean match = false;
        if (filterType == 0 || filterType == 1) {
            match = fullMatch ? id.equals(filter) : id.contains(filter);
        }
        if (match) {
            return true;
        }
        if (filterType == 0 || filterType == 2) {
            match = fullMatch ? name.equals(filter) : name.contains(filter);
        }
        if (match) {
            return true;
        }
        if (filterType == 0 || filterType == 2) {
            match = fullMatch ? desc.equals(filter) : desc.contains(filter);
        }
        return match;
    }

    /**
     * 检查发型/脸型的性别和颜色是否匹配
     * @param infType 类型
     * @param idStr ID字符串
     * @param gender 性别 (0:男, 1:女, 2:通用)
     * @param color 颜色 (0-7)
     * @return 是否匹配
     */
    private boolean checkHairFaceLogic(InformationType infType, String idStr, Integer gender, Integer color) {
        if (infType != InformationType.HAIR && infType != InformationType.FACE) {
            return true;
        }
        if (gender == null && color == null) {
            return true;
        }

        try {
            int id = Integer.parseInt(idStr);
            
            // 颜色检查 (ID最后一位)
            if (color != null) {
                int itemColor = id % 10;
                if (itemColor != color) {
                    return false;
                }
            }

            // 性别检查
            if (gender != null && gender != 2) { // 2为通用/全部，不做性别过滤
                if (infType == InformationType.HAIR) {
                    // 发型ID规律: 30xxx(男), 33xxx(男), 31xxx(女), 34xxx(女)
                    // 32xxx 通常是通用，但也可能混杂
                    int prefix = id / 1000;
                    if (gender == 0) { // 男
                        if (prefix != 30 && prefix != 33 && prefix != 32) return false;
                    } else if (gender == 1) { // 女
                        if (prefix != 31 && prefix != 34 && prefix != 32) return false;
                    }
                } else if (infType == InformationType.FACE) {
                    // 脸型ID规律: 20xxx(男), 21xxx(女), 22xxx(通用?)
                    int prefix = id / 1000;
                    if (gender == 0) { // 男
                        if (prefix != 20 && prefix != 22) return false;
                    } else if (gender == 1) { // 女
                        if (prefix != 21 && prefix != 22) return false;
                    }
                }
            }
            
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
