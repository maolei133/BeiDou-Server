package org.gms.controller;

import com.mybatisflex.core.paginate.Page;
import lombok.AllArgsConstructor;
import org.gms.model.dto.*;
import org.gms.service.MonsterBookService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monsterbook/v1")
@AllArgsConstructor
public class MonsterBookController {
    private final MonsterBookService monsterBookService;

    @PostMapping("/list")
    public ResultBody<Page<MonsterBookRtnDTO>> list(@RequestBody SubmitBody<MonsterBookSearchReqDTO> body) {
        return ResultBody.success(monsterBookService.search(body.getData()));
    }

    @PostMapping("/batchDelete")
    public ResultBody<Object> batchDelete(@RequestBody SubmitBody<MonsterBookBatchDeleteReqDTO> body) {
        monsterBookService.batchDelete(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/batchAdd")
    public ResultBody<Object> batchAdd(@RequestBody SubmitBody<MonsterBookBatchAddReqDTO> body) {
        monsterBookService.batchAdd(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/batchUpdate")
    public ResultBody<Object> batchUpdate(@RequestBody SubmitBody<MonsterBookBatchUpdateReqDTO> body) {
        monsterBookService.batchUpdate(body.getData());
        return ResultBody.success();
    }

    @PostMapping("/transfer")
    public ResultBody<Object> transfer(@RequestBody SubmitBody<MonsterBookTransferReqDTO> body) {
        monsterBookService.transfer(body.getData());
        return ResultBody.success();
    }
}
