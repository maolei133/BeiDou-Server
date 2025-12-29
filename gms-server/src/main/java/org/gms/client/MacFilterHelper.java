package org.gms.client;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.dao.entity.MacfiltersDO;
import org.gms.dao.mapper.MacfiltersMapper;
import org.gms.util.SpringContextUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * MAC过滤规则操作工具类
 * 提供对macfilters表的增删改查操作
 * 已改造为使用 MyBatis DAO
 */
public class MacFilterHelper {

    private static MacfiltersMapper getMapper() {
        return SpringContextUtil.getBean(MacfiltersMapper.class);
    }

    /**
     * 查询所有MAC过滤规则
     * @return 过滤规则列表
     */
    public static List<String> getAllFilters() {
        MacfiltersMapper mapper = getMapper();
        if (mapper == null) {
            return new ArrayList<>();
        }
        List<MacfiltersDO> list = mapper.selectAll();
        return list.stream().map(MacfiltersDO::getFilter).collect(Collectors.toList());
    }

    /**
     * 添加MAC过滤规则
     * @param filter 过滤规则
     * @return 是否添加成功
     */
    public static boolean addFilter(String filter) {
        MacfiltersMapper mapper = getMapper();
        if (mapper == null) {
            return false;
        }
        MacfiltersDO entity = new MacfiltersDO();
        entity.setFilter(filter);
        return mapper.insert(entity) > 0;
    }

    /**
     * 检查MAC地址列表，返回未匹配过滤规则的MAC地址
     * @param macs 待检查的MAC地址列表
     * @return 未匹配过滤规则的MAC地址列表
     */
    public static List<String> checkMacs(List<String> macs) {
        List<String> unmatchedMacs = new ArrayList<>();
        List<String> filters = getAllFilters();

        for (String mac : macs) {
            boolean matched = false;
            for (String filter : filters) {
                if (mac.matches(filter)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                unmatchedMacs.add(mac);
            }
        }

        return unmatchedMacs;
    }

    /**
     * 删除MAC过滤规则
     * @param filter 过滤规则
     * @return 是否删除成功
     */
    public static boolean deleteFilter(String filter) {
        MacfiltersMapper mapper = getMapper();
        if (mapper == null) {
            return false;
        }
        try {
             return mapper.deleteByQuery(new QueryWrapper().eq("filter", filter)) > 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 检查MAC地址是否匹配任何过滤规则
     * @param mac MAC地址
     * @return 是否匹配
     */
    public static boolean isMacFiltered(String mac) {
        List<String> filters = getAllFilters();
        for (String filter : filters) {
            if (mac.matches(filter)) {
                return true;
            }
        }
        return false;
    }
}
