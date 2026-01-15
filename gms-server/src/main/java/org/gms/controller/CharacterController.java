package org.gms.controller;

import com.mybatisflex.core.paginate.Page;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.gms.constants.api.ApiConstant;
import org.gms.dao.entity.ExtendValueDO;
import org.gms.model.dto.*;
import org.gms.service.CharacterService;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/character")
public class CharacterController {
    private final CharacterService characterService;

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "调整玩家个人倍率，extendName为：expRate | mesoRate | dropRate")
    @PostMapping("/" + ApiConstant.LATEST + "/updateRate")
    public ResultBody<Object> updateRate(@RequestBody SubmitBody<ExtendValueDO> submitBody) {
        characterService.updateRate(submitBody.getData());
        return ResultBody.success();
    }


    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "重置玩家个人倍率，extendName为：expRate | mesoRate | dropRate")
    @PostMapping("/" + ApiConstant.LATEST + "/resetRate")
    public ResultBody<Object> resetRate(@RequestBody SubmitBody<ExtendValueDO> submitBody) {
        characterService.resetRate(submitBody.getData());
        return ResultBody.success();
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "重置玩家个人所有倍率")
    @GetMapping("/" + ApiConstant.LATEST + "/resetRates")
    public ResultBody<Object> resetRates(@RequestBody SubmitBody<ExtendValueDO> submitBody) {
        characterService.resetRates(submitBody.getData());
        return ResultBody.success();
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "查询在线玩家列表")
    @PostMapping("/" + ApiConstant.LATEST + "/online/list")
    public ResultBody<Page<ChrOnlineListRtnDTO>> onlineList(@RequestBody SubmitBody<ChrOnlineListReqDTO> submitBody) {
        return ResultBody.success(characterService.getChrOnlineList(submitBody.getData()));
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "更新角色信息")
    @PostMapping("/" + ApiConstant.LATEST + "/update")
    public ResultBody<Object> updateCharacter(@RequestBody SubmitBody<UpdateCharacterReqDTO> submitBody) {
        characterService.updateCharacter(submitBody.getData());
        return ResultBody.success();
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "获取角色详情")
    @PostMapping("/" + ApiConstant.LATEST + "/detail")
    public ResultBody<ChrDetailRtnDTO> detail(@RequestBody SubmitBody<ChrIdDTO> submitBody) {
        return ResultBody.success(characterService.getCharacterDetail(submitBody.getData().getId()));
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "断开玩家连接")
    @PostMapping("/" + ApiConstant.LATEST + "/disconnect")
    public ResultBody<Object> disconnect(@RequestBody SubmitBody<DisconnectReqDTO> submitBody) {
        characterService.disconnect(submitBody.getData());
        return ResultBody.success();
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "封禁玩家")
    @PostMapping("/" + ApiConstant.LATEST + "/ban")
    public ResultBody<Object> ban(@RequestBody SubmitBody<BanPlayerReqDTO> submitBody) {
        characterService.ban(submitBody.getData());
        return ResultBody.success();
    }

    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "获取玩家封禁信息(IP/MAC/HWID)")
    @PostMapping("/" + ApiConstant.LATEST + "/banInfo")
    public ResultBody<BanInfoRtnDTO> getBanInfo(@RequestBody SubmitBody<ChrIdDTO> submitBody) {
        return ResultBody.success(characterService.getBanInfo(submitBody.getData().getId()));
    }
    
    @Tag(name = "/character/" + ApiConstant.LATEST)
    @Operation(summary = "解封玩家")
    @PostMapping("/" + ApiConstant.LATEST + "/unban")
    public ResultBody<Object> unban(@RequestBody SubmitBody<ChrIdDTO> submitBody) {
        characterService.unban(submitBody.getData().getId());
        return ResultBody.success();
    }
}
