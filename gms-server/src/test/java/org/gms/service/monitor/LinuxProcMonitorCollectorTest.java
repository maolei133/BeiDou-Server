package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LinuxProcMonitorCollectorTest {

    @Test
    void selectedInterfaceUsesItsOwnNetworkRate() {
        LinuxProcMonitorCollector collector = new LinuxProcMonitorCollector();

        SystemMetricsSample first = collector.applyNetworkRatesForTest(
                counters("eth0", 1000L, 500L, "eth1", 4000L, 800L),
                null,
                "eth1",
                1.0D
        );
        SystemMetricsSample second = collector.applyNetworkRatesForTest(
                counters("eth0", 1600L, 900L, "eth1", 7000L, 1800L),
                counters("eth0", 1000L, 500L, "eth1", 4000L, 800L),
                "eth1",
                2.0D
        );

        assertEquals(null, first.getNetworkRxBytesPerSecond());
        assertEquals(1500D, second.getNetworkRxBytesPerSecond());
        assertEquals(500D, second.getNetworkTxBytesPerSecond());
        assertEquals(300D, second.getNetworkRates().get("eth0").getRxBytesPerSecond());
    }

    private static LinuxProcMonitorCollector.NetCounters counters(String name1, long rx1, long tx1,
                                                                  String name2, long rx2, long tx2) {
        LinuxProcMonitorCollector.NetCounters counters = new LinuxProcMonitorCollector.NetCounters();
        counters.put(name1, rx1, tx1);
        counters.put(name2, rx2, tx2);
        return counters;
    }
}
