package org.gms.controller;

import com.mybatisflex.core.paginate.Page;
import lombok.AllArgsConstructor;
import org.gms.model.dto.*;
import org.gms.service.MonsterBookService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/monsterbook/v1")
@AllArgsConstructor
public class MonsterBookController {
    private final MonsterBookService monsterBookService;

    @PostMapping("/list")
    public ResultBody<Page<MonsterBookDTO.Rtn>> list(@RequestBody SubmitBody<MonsterBookDTO.SearchReq> body) {
        return ResultBody.success(monsterBookService.search(body.getData()));
    }

    @PostMapping("/batchDelete")
    public ResultBody<Object> batchDelete(@RequestBody SubmitBody<MonsterBookDTO.BatchDeleteReq> body) {
        monsterBookService.batchDelete(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/batchAdd")
    public ResultBody<Object> batchAdd(@RequestBody SubmitBody<MonsterBookDTO.BatchAddReq> body) {
        monsterBookService.batchAdd(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/batchUpdate")
    public ResultBody<Object> batchUpdate(@RequestBody SubmitBody<MonsterBookDTO.BatchUpdateReq> body) {
        monsterBookService.batchUpdate(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/transfer")
    public ResultBody<Object> transfer(@RequestBody SubmitBody<MonsterBookDTO.TransferReq> body) {
        monsterBookService.transfer(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/getCardNames")
    public ResultBody<Map<Integer, String>> getCardNames(@RequestBody SubmitBody<MonsterBookDTO.SearchReq> body) {
        return ResultBody.success(monsterBookService.getCardNames(body.getData()));
    }
}
