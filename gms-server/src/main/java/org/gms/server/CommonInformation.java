package org.gms.server;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import org.gms.constants.api.InformationType;
import org.gms.constants.inventory.EquipType;
import org.gms.dao.entity.MonstercarddataDO;
import org.gms.dao.mapper.MonstercarddataMapper;
import org.gms.exception.BizException;
import org.gms.model.pojo.InformationSearch;
import org.gms.model.pojo.InformationResult;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.server.life.MonsterInformationProvider;
import org.gms.util.I18nUtil;
import org.gms.util.RequireUtil;
import org.gms.util.SpringContextUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CommonInformation {
    private static CommonInformation instance;
    private final DataProvider stringData;
    private List<InformationResult> cachedMaps;
    private List<String> cachedEquipCategories;
    private List<InformationResult> cachedMonsterCards;

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
     * 获取所有装备分类
     */
    public List<String> getEquipCategories() {
        if (cachedEquipCategories != null) {
            return cachedEquipCategories;
        }
        synchronized (this) {
            if (cachedEquipCategories != null) {
                return cachedEquipCategories;
            }
            List<String> categories = new ArrayList<>();
            Data data = stringData.getData("Eqp.img");
            if (data != null) {
                Data eqpNode = data.getChildByPath("Eqp");
                if (eqpNode != null) {
                    for (Data child : eqpNode.getChildren()) {
                        categories.add(child.getName());
                    }
                }
            }
            Collections.sort(categories);
            cachedEquipCategories = categories;
            return cachedEquipCategories;
        }
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
            total += searchXML(results, infType, condition);
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

    private long searchXML(List<InformationResult> results, InformationType infType, InformationSearch condition) {
        Data data;
        long count = 0;
        
        String filter = condition.getFilter();
        int filterType = condition.getFilterType();
        boolean fullMatch = condition.isFullMatch();
        Integer page = condition.getPage();
        Integer pageSize = condition.getPageSize();
        Integer gender = condition.getGender();
        Integer color = condition.getColor();
        String category = condition.getCategory();
        String subCategory = condition.getSubCategory();

        switch (infType) {
            case CASH -> {
                data = stringData.getData("Cash.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case CONSUME -> {
                data = stringData.getData("Consume.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case EQP -> {
                Data eqpData = stringData.getData("Eqp.img").getChildByPath("Eqp");
                if (category != null && !category.isEmpty()) {
                    // 如果指定了分类，只搜索该分类
                    // 特殊处理：如果 category 是 Accessory，并且 subCategory 是 RING，
                    // 且 WZ 结构中 Ring 是独立的一级分类，则需要去 Ring 节点下搜索
                    if ("Accessory".equals(category) && "RING".equals(subCategory)) {
                        Data ringNode = eqpData.getChildByPath("Ring");
                        if (ringNode != null) {
                            count += addResult(results, infType, ringNode, filter, filterType, fullMatch, page, pageSize, gender, color, subCategory);
                        }
                    } else {
                        Data child = eqpData.getChildByPath(category);
                        if (child != null) {
                            count += addResult(results, infType, child, filter, filterType, fullMatch, page, pageSize, gender, color, subCategory);
                        }
                    }
                } else {
                    // 否则搜索所有分类
                    for (Data child : eqpData.getChildren()) {
                        count += addResult(results, infType, child, filter, filterType, fullMatch, page, pageSize, gender, color, subCategory);
                    }
                }
            }
            case ETC -> {
                data = stringData.getData("Etc.img").getChildByPath("Etc");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case INS -> {
                data = stringData.getData("Ins.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case MAP -> {
                data = stringData.getData("Map.img");
                for (Data child : data.getChildren()) {
                    count += addMapResult(results, infType, child, filter, filterType, fullMatch, page, pageSize);
                }
            }
            case MOB -> {
                data = stringData.getData("Mob.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case NPC -> {
                data = stringData.getData("Npc.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case PET -> {
                data = stringData.getData("Pet.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case SKILL -> {
                data = stringData.getData("Skill.img");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case HAIR -> {
                data = stringData.getData("Eqp.img").getChildByPath("Eqp/Hair");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case FACE -> {
                data = stringData.getData("Eqp.img").getChildByPath("Eqp/Face");
                count = addResult(results, infType, data, filter, filterType, fullMatch, page, pageSize, gender, color, null);
            }
            case MONSTER_CARD -> {
                count = searchMonsterCards(results, condition);
            }
        }
        return count;
    }

    private long searchMonsterCards(List<InformationResult> results, InformationSearch condition) {
        List<InformationResult> allCards = getAllMonsterCards();
        
        String filter = condition.getFilter();
        int filterType = condition.getFilterType();
        boolean fullMatch = condition.isFullMatch();
        
        // 内存过滤
        List<InformationResult> filtered = allCards.stream()
            .filter(card -> isMatch(String.valueOf(card.getId()), card.getName(), card.getDesc(), filter, filterType, fullMatch))
            .collect(Collectors.toList());
            
        long matchCount = filtered.size();
        
        int page = condition.getPage() != null ? condition.getPage() : 1;
        int pageSize = condition.getPageSize() != null ? condition.getPageSize() : 20;
        
        int start = (page - 1) * pageSize;
        int end = Math.min(start + pageSize, filtered.size());
        
        if (start < filtered.size()) {
            results.addAll(filtered.subList(start, end));
        }
        
        return matchCount;
    }
    
    private List<InformationResult> getAllMonsterCards() {
        if (cachedMonsterCards != null) {
            return cachedMonsterCards;
        }
        synchronized (this) {
            if (cachedMonsterCards != null) {
                return cachedMonsterCards;
            }
            
            MonstercarddataMapper mapper = SpringContextUtil.getBean(MonstercarddataMapper.class);
            if (mapper == null) return new ArrayList<>();
            
            List<MonstercarddataDO> list = mapper.selectListByQuery(QueryWrapper.create());
            List<InformationResult> results = new ArrayList<>();
            
            for (MonstercarddataDO data : list) {
                String name = "Unknown";
                if (data.getMobid() != null) {
                    name = MonsterInformationProvider.getInstance().getMobNameFromId(data.getMobid());
                }
                
                results.add(InformationResult.builder()
                        .type(InformationType.MONSTER_CARD.getType())
                        .id(data.getCardid())
                        .name(name)
                        .desc("Mob ID: " + data.getMobid())
                        .build());
            }
            
            cachedMonsterCards = results;
            return cachedMonsterCards;
        }
    }

    private long addResult(List<InformationResult> results, InformationType infType, Data data, String filter, int filterType, boolean fullMatch, Integer page, Integer pageSize, Integer gender, Integer color, String subCategory) {
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

            // 检查子分类
            if (subCategory != null && !subCategory.isEmpty()) {
                if (!checkSubCategory(id, subCategory)) {
                    continue;
                }
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

    /**
     * 检查物品ID是否属于指定的子分类
     * @param idStr 物品ID字符串
     * @param subCategory 子分类名称 (对应 EquipType 枚举名)
     * @return 是否匹配
     */
    private boolean checkSubCategory(String idStr, String subCategory) {
        try {
            int id = Integer.parseInt(idStr);
            EquipType type = EquipType.valueOf(subCategory);
            
            // 特殊处理：EquipType 的逻辑是基于 ID 前缀的
            // EquipType.getEquipTypeById(id) 会返回该 ID 对应的类型
            // 我们只需要比较两者是否相等
            return EquipType.getEquipTypeById(id) == type;
        } catch (IllegalArgumentException | NullPointerException e) {
            // 如果 subCategory 不是有效的 EquipType 枚举名，或者 ID 解析失败
            return false;
        }
    }
}
