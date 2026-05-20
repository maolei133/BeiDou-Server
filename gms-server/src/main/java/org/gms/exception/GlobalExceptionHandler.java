package org.gms.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.gms.model.dto.ResultBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Optional;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final int PARAMETER_ERROR_CODE = 10001;
    private static final int AUTHENTICATION_ERROR_CODE = 20002;
    private static final int ACCESS_DENIED_ERROR_CODE = 30001;
    private static final int RESOURCE_NOT_FOUND_CODE = 40404;
    private static final int SYSTEM_ERROR_CODE = 50000;

    /**
     * 获取客户端真实IP地址
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // 对于通过多个代理的情况，第一个IP为客户端真实IP
        if (ip != null && ip.contains(",")) {
            ip = ip.substring(0, ip.indexOf(",")).trim();
        }

        return ip;
    }

    /**
     * 获取尝试登录的账号信息
     */
    private String getAttemptedUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal())) {
            return authentication.getName();
        }

        return "未知用户";
    }

    /**
     * 记录可预期业务失败，不打印堆栈，避免污染系统错误日志。
     */
    private void logBusinessFailure(HttpServletRequest request, Exception e, String exceptionType, boolean warn) {
        String clientIp = getClientIp(request);
        String path = request.getRequestURI();
        String method = request.getMethod();
        String username = getAttemptedUsername();
        String message = Optional.ofNullable(e.getMessage()).orElse("无异常消息");

        if (warn) {
            logger.warn("{} - IP: {}, 用户: {}, 路径: {} [{}], 错误详情: {}",
                    exceptionType, clientIp, username, path, method, message);
        } else {
            logger.info("{} - IP: {}, 用户: {}, 路径: {} [{}], 错误详情: {}",
                    exceptionType, clientIp, username, path, method, message);
        }
    }

    /**
     * 记录系统异常详细信息，保留完整堆栈。
     */
    private void logSystemException(HttpServletRequest request, Exception e, String exceptionType) {
        String clientIp = getClientIp(request);
        String path = request.getRequestURI();
        String method = request.getMethod();
        String username = getAttemptedUsername();

        // 获取User-Agent信息
        String userAgent = request.getHeader("User-Agent");

        logger.error("{} - IP: {}, 用户: {}, 路径: {} [{}], User-Agent: {}, 错误详情: {}",
                exceptionType, clientIp, username, path, method, userAgent, e.getMessage(), e);
    }

    /**
     * 处理自定义的业务异常。
     */
    @ExceptionHandler(value = BizException.class)
    @ResponseBody
    public ResultBody<Object> bizExceptionHandler(HttpServletRequest req, BizException e) {
        logBusinessFailure(req, e, "业务异常", true);
        Integer code = Optional.ofNullable(e.getErrorCode()).orElse(PARAMETER_ERROR_CODE);
        String message = Optional.ofNullable(e.getErrorMsg()).orElse("参数错误");
        return ResultBody.error(req, code, message);
    }

    /**
     * 处理请求体、表单和 Bean Validation 参数校验异常。
     */
    @ExceptionHandler({
            MethodArgumentNotValidException.class,
            BindException.class,
            HandlerMethodValidationException.class,
            MissingServletRequestParameterException.class,
            HttpMessageNotReadableException.class,
            IllegalArgumentException.class,
            ConstraintViolationException.class
    })
    @ResponseBody
    public ResultBody<Object> parameterExceptionHandler(HttpServletRequest req, Exception e) {
        String message = resolveParameterMessage(e);
        logBusinessFailure(req, e, "参数校验失败", true);
        return ResultBody.error(req, PARAMETER_ERROR_CODE, message);
    }

    /**
     * 处理认证失败异常。
     */
    @ExceptionHandler(AuthenticationException.class)
    @ResponseBody
    public ResultBody<Object> authenticationExceptionHandler(HttpServletRequest req, AuthenticationException e) {
        logBusinessFailure(req, e, "认证失败", true);
        return ResultBody.error(req, AUTHENTICATION_ERROR_CODE, "认证失败或登录已失效");
    }

    /**
     * 处理权限不足异常。
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseBody
    public ResultBody<Object> accessDeniedExceptionHandler(HttpServletRequest req, AccessDeniedException e) {
        logBusinessFailure(req, e, "权限不足", true);
        return ResultBody.error(req, ACCESS_DENIED_ERROR_CODE, "权限不足，禁止访问");
    }

    /**
     * 处理资源未找到异常。
     */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    @ResponseBody
    public ResultBody<Object> notFoundExceptionHandler(HttpServletRequest req, Exception e) {
        logBusinessFailure(req, e, "请求资源未找到", false);
        return ResultBody.error(req, RESOURCE_NOT_FOUND_CODE, "请求的资源不存在");
    }

    /**
     * 处理请求方法不支持的异常。
     */
    @ExceptionHandler(value = {ServletException.class, HttpRequestMethodNotSupportedException.class})
    @ResponseBody
    public ResultBody<Object> servletExceptionHandler(HttpServletRequest req, Exception e) {
        logBusinessFailure(req, e, "请求不被支持", true);
        return ResultBody.error(req, PARAMETER_ERROR_CODE, e.getMessage());
    }

    /**
     * 处理其他未捕获的系统异常。
     */
    @ExceptionHandler(value = Exception.class)
    @ResponseBody
    public ResultBody<Object> exceptionHandler(HttpServletRequest req, Exception e) {
        logSystemException(req, e, "系统内部错误");
        return ResultBody.error(req, SYSTEM_ERROR_CODE, "服务器内部错误!");
    }

    private String resolveParameterMessage(Exception e) {
        if (e instanceof MethodArgumentNotValidException ex) {
            return ex.getBindingResult().getFieldErrors().stream()
                    .map(this::formatFieldError)
                    .findFirst()
                    .orElse("参数校验失败");
        }
        if (e instanceof BindException ex) {
            return ex.getBindingResult().getFieldErrors().stream()
                    .map(this::formatFieldError)
                    .findFirst()
                    .orElse("参数绑定失败");
        }
        if (e instanceof HandlerMethodValidationException ex) {
            String message = ex.getAllErrors().stream()
                    .map(error -> Optional.ofNullable(error.getDefaultMessage()).orElse(error.toString()))
                    .collect(Collectors.joining("；"));
            return message.isBlank() ? "参数校验失败" : message;
        }
        if (e instanceof MissingServletRequestParameterException ex) {
            return "缺少必填参数: " + ex.getParameterName();
        }
        if (e instanceof HttpMessageNotReadableException) {
            return "请求数据格式不正确";
        }
        return Optional.ofNullable(e.getMessage()).orElse("参数错误");
    }

    private String formatFieldError(FieldError error) {
        String message = Optional.ofNullable(error.getDefaultMessage()).orElse("参数错误");
        return error.getField() + ": " + message;
    }
}
