package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CpuMonitorConfigDTO {
    private List<Rule> rules;

    public static CpuMonitorConfigDTO defaults() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder().p(0.30D).lv("WARN").build());
        rules.add(Rule.builder().p(0.50D).lv("WARN").build());
        rules.add(Rule.builder().p(0.70D).lv("ERROR").build());
        rules.add(Rule.builder().p(0.90D).lv("ERROR").build());
        return CpuMonitorConfigDTO.builder().rules(rules).build();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Rule {
        private Double p;
        private String lv;
    }
}
