package org.gms.controller;

import com.mybatisflex.core.paginate.Page;
import lombok.AllArgsConstructor;
import org.gms.model.dto.DueyPackageRtnDTO;
import org.gms.model.dto.DueySearchReqDTO;
import org.gms.model.dto.ResultBody;
import org.gms.model.dto.SendDueyReqDTO;
import org.gms.model.dto.SubmitBody;
import org.gms.service.DueyService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/duey/v1")
@AllArgsConstructor
public class DueyController {

    private final DueyService dueyService;

    @GetMapping("/list")
    public ResultBody<Page<DueyPackageRtnDTO>> getDueyList(DueySearchReqDTO req) {
        return ResultBody.success(dueyService.getDueyList(req));
    }

    @DeleteMapping("/{id}")
    public ResultBody<Void> deleteDueyPackage(@PathVariable Long id) {
        dueyService.deleteDueyPackage(id);
        return ResultBody.success();
    }

    @PostMapping("/send")
    public ResultBody<Void> sendDueyPackage(@RequestBody SubmitBody<SendDueyReqDTO> body) {
        dueyService.sendDueyPackage(body.getData());
        return ResultBody.success();
    }
}
