package org.gms.model.dto;

import com.alibaba.fastjson2.JSONObject;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import org.gms.exception.BaseErrorInfoInterface;
import org.gms.exception.BizExceptionEnum;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.UUID;

@Data
public class ResultBody<T> {
    private Integer code;
    private String message;
    private String responseId;
    private T data;
    private Long timestamp;
    private String path;

    public ResultBody() {
    }

    public ResultBody(BaseErrorInfoInterface errorInfo) {
        this.code = errorInfo.getResultCode();
        this.message = errorInfo.getResultMsg();
    }

    public static <T> ResultBody<T> success() {
        return success(null);
    }

    public static <T> ResultBody<T> success(T data) {
        ResultBody<T> rb = new ResultBody<>();
        applyRequestMetadata(rb, null);
        rb.setResponseId(UUID.randomUUID().toString());
        rb.setCode(BizExceptionEnum.SUCCESS.getResultCode());
        rb.setMessage(BizExceptionEnum.SUCCESS.getResultMsg());
        rb.setData(data);
        return rb;
    }

    public static <T> ResultBody<T> ok(T data) {
        return success(data);
    }

    public static <T> ResultBody<T> success(SubmitBody<?> request, T data) {
        ResultBody<T> rb = new ResultBody<>();
        applyRequestMetadata(rb, null);
        rb.setResponseId(request.getRequestId());
        rb.setCode(BizExceptionEnum.SUCCESS.getResultCode());
        rb.setMessage(BizExceptionEnum.SUCCESS.getResultMsg());
        rb.setData(data);
        return rb;
    }

    public static <T> ResultBody<T> error(BaseErrorInfoInterface errorInfo) {
        return error(errorInfo.getResultCode(), errorInfo.getResultMsg());
    }

    public static <T> ResultBody<T> error(String message) {
        return error(10001, message);
    }

    public static <T> ResultBody<T> error(Integer code, String message) {
        HttpServletRequest req = null;
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                req = attributes.getRequest();
            }
        } catch (Exception e) {
            // ignore
        }
        return error(req, code, message);
    }

    public static <T> ResultBody<T> error(HttpServletRequest req, BaseErrorInfoInterface errorInfo) {
        return error(req, errorInfo.getResultCode(), errorInfo.getResultMsg());
    }

    public static <T> ResultBody<T> error(HttpServletRequest req, String message) {
        return error(req, -1, message);
    }

    public static <T> ResultBody<T> error(HttpServletRequest req, Integer code, String message) {
        ResultBody<T> rb = new ResultBody<>();
        applyRequestMetadata(rb, req);
        // 异常处理阶段不要再次读取 request body，避免 @RequestBody 已消费后触发系统 ERROR 日志。
        rb.setResponseId(UUID.randomUUID().toString());
        rb.setCode(code);
        rb.setMessage(message);
        rb.setData(null);
        return rb;
    }

    private static void applyRequestMetadata(ResultBody<?> rb, HttpServletRequest req) {
        rb.setTimestamp(System.currentTimeMillis());
        HttpServletRequest currentReq = req;
        if (currentReq == null) {
            try {
                ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
                if (attributes != null) {
                    currentReq = attributes.getRequest();
                }
            } catch (Exception e) {
                // ignore
            }
        }
        if (currentReq != null) {
            rb.setPath(currentReq.getRequestURI());
        }
    }

    @Override
    public String toString() {
        return JSONObject.toJSONString(this);
    }
}
