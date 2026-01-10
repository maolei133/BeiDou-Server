package org.gms.controller;


import com.mybatisflex.core.paginate.Page;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.gms.constants.api.ApiConstant;
import org.gms.model.dto.*;
import org.gms.model.pojo.InformationSearch;
import org.gms.model.pojo.InformationResult;
import org.gms.service.CommonService;
import org.gms.model.dto.SubmitBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@AllArgsConstructor
@RequestMapping("/common")
public class CommonController {
    private final CommonService commonService;


    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "查询装备基础属性信息")
    @PostMapping("/" + ApiConstant.LATEST + "/getEquipmentInfoByItemId")
    public ResultBody<Object> getEquipmentInfoByItemId(@RequestBody SubmitBody<EquipmentInfoReqDTO> submitBody) {
        return ResultBody.success(commonService.getEquipmentInfoByItemId(submitBody.getData()));
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "查询道具基础属性信息")
    @PostMapping("/" + ApiConstant.LATEST + "/getItemInfoByItemId")
    public ResultBody<Object> getItemInfoByItemId(@RequestBody SubmitBody<ItemInfoReqDTO> submitBody) {
        return ResultBody.success(commonService.getItemInfoByItemId(submitBody.getData()));
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "查询所有世界中当前在线玩家数量")
    @PostMapping("/" + ApiConstant.LATEST + "/getAllWorldsOnlinePlayersCount")
    public ResultBody<Integer> getAllWorldsOnlinePlayersCount(@RequestBody SubmitBody<ServerInfoReqDto> submitBody) {
        return ResultBody.success(commonService.getAllWorldsOnlinePlayersCount(submitBody.getData().getWorldIdList()));
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "资料查询，根据id或者name查询对应信息")
    @PostMapping("/" + ApiConstant.LATEST + "/informationSearch")
    public ResultBody<Page<InformationResult>> informationSearch(@RequestBody SubmitBody<InformationSearch> submitBody) {
        return ResultBody.success(commonService.getInformation(submitBody.getData()));
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "获取所有地图信息")
    @GetMapping("/" + ApiConstant.LATEST + "/getAllMaps")
    public ResultBody<List<InformationResult>> getAllMaps() {
        return ResultBody.success(commonService.getAllMaps());
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "获取所有区域名称")
    @GetMapping("/" + ApiConstant.LATEST + "/getStreetNames")
    public ResultBody<List<String>> getStreetNames() {
        return ResultBody.success(commonService.getStreetNames());
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "根据区域名称获取地图")
    @GetMapping("/" + ApiConstant.LATEST + "/getMapsByStreetName")
    public ResultBody<List<InformationResult>> getMapsByStreetName(@RequestParam String streetName) {
        return ResultBody.success(commonService.getMapsByStreetName(streetName));
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "获取所有职业信息")
    @GetMapping("/" + ApiConstant.LATEST + "/getJobs")
    public ResultBody<List<InformationResult>> getJobs() {
        return ResultBody.success(commonService.getJobs());
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "获取所有肤色信息")
    @GetMapping("/" + ApiConstant.LATEST + "/getSkinColors")
    public ResultBody<List<InformationResult>> getSkinColors() {
        return ResultBody.success(commonService.getSkinColors());
    }

    @Tag(name = "/common/" + ApiConstant.LATEST)
    @Operation(summary = "获取所有家族信息")
    @GetMapping("/" + ApiConstant.LATEST + "/getGuilds")
    public ResultBody<List<InformationResult>> getGuilds() {
        return ResultBody.success(commonService.getGuilds());
    }
}
