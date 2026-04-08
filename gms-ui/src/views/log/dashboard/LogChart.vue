<template>
  <div
    ref="cardRef"
    class="log-chart-wrapper"
    :style="{ height: height + 'px' }"
  >
    <a-card
      class="log-chart-card"
      :loading="loading"
      :bordered="false"
      hoverable
    >
      <template #title>
        <div class="chart-header" @dblclick="handleTitleEdit">
          <span v-if="!isEditingTitle" class="chart-title">{{ title }}</span>
          <a-input
            v-else
            ref="titleInputRef"
            v-model="editTitleValue"
            size="small"
            @blur="saveTitle"
            @press-enter="saveTitle"
          />
        </div>
      </template>
      <template #extra>
        <a-space>
          <a-button type="text" size="mini" @click="handleConfig">
            <template #icon><icon-settings /></template>
          </a-button>
          <a-button type="text" size="mini" @click="fetchData">
            <template #icon><icon-refresh /></template>
          </a-button>
          <a-button
            type="text"
            size="mini"
            status="danger"
            @click.stop="$emit('remove')"
          >
            <template #icon><icon-delete /></template>
          </a-button>
        </a-space>
      </template>
      <div class="chart-container">
        <a-empty v-if="error" :description="error" />
        <v-chart
          v-else
          class="chart"
          :option="chartOption"
          autoresize
          :loading="loading"
        />
      </div>
    </a-card>

    <div class="resize-handle" @mousedown="startResize">
      <icon-drag-dot-vertical />
    </div>
  </div>
</template>

<script setup lang="ts">
  import { ref, computed, onMounted, watch, nextTick } from 'vue';
  import { use } from 'echarts/core';
  import { CanvasRenderer } from 'echarts/renderers';
  import {
    LineChart,
    BarChart,
    PieChart,
    ScatterChart,
    RadarChart,
    FunnelChart,
    GaugeChart,
    HeatmapChart,
    CandlestickChart,
  } from 'echarts/charts';
  import {
    GridComponent,
    TooltipComponent,
    LegendComponent,
    TitleComponent,
    VisualMapComponent,
  } from 'echarts/components';
  import VChart from 'vue-echarts';
  import { queryLogs, LabelValue } from '@/api/log';
  import { useI18n } from 'vue-i18n';

  use([
    CanvasRenderer,
    LineChart,
    BarChart,
    PieChart,
    ScatterChart,
    RadarChart,
    FunnelChart,
    GaugeChart,
    HeatmapChart,
    CandlestickChart,
    GridComponent,
    TooltipComponent,
    LegendComponent,
    TitleComponent,
    VisualMapComponent,
  ]);

  const props = defineProps<{
    id: string;
    title: string;
    type: string;
    query: string;
    height: number;
    width: number;
    range?: string;
    allOptions: {
      modules: LabelValue[];
      actions: LabelValue[];
      traceabilityActionTypes: LabelValue[];
      traceabilityActionSourceTypes: LabelValue[];
    };
  }>();

  const emit = defineEmits([
    'remove',
    'update:title',
    'update:height',
    'update:width',
    'config',
    'resizeStart',
    'resizeEnd',
  ]);
  const { t } = useI18n();

  const loading = ref(false);
  const error = ref('');
  const chartData = ref<any[]>([]);
  const isEditingTitle = ref(false);
  const editTitleValue = ref('');
  const titleInputRef = ref<HTMLInputElement | null>(null);
  const cardRef = ref<HTMLElement | null>(null);

  const handleTitleEdit = () => {
    editTitleValue.value = props.title;
    isEditingTitle.value = true;
    nextTick(() => {
      titleInputRef.value?.focus();
    });
  };

  const saveTitle = () => {
    if (editTitleValue.value.trim()) {
      emit('update:title', editTitleValue.value);
    }
    isEditingTitle.value = false;
  };

  const handleConfig = () => {
    emit('config');
  };

  const startResize = (e: MouseEvent) => {
    e.preventDefault();
    emit('resizeStart'); // 通知父组件开始调整大小

    const startX = e.clientX;
    const startY = e.clientY;
    const startHeight = props.height;
    const startWidth = props.width;

    // 16px 是网格间距
    const gridStep = 16;

    const handleMouseMove = (moveEvent: MouseEvent) => {
      // 1. 计算高度变化
      const deltaY = moveEvent.clientY - startY;
      const newHeightRaw = Math.max(200, startHeight + deltaY);
      // 对齐到最近的 16px 倍数
      const newHeight = Math.round(newHeightRaw / gridStep) * gridStep;

      if (newHeight !== props.height) {
        emit('update:height', newHeight);
      }

      // 2. 计算宽度变化 (改为像素级对齐)
      const deltaX = moveEvent.clientX - startX;
      // 最小宽度限制为 200px (约 12 个网格)
      const newWidthRaw = Math.max(200, startWidth + deltaX);
      // 对齐到最近的 16px 倍数
      const newWidth = Math.round(newWidthRaw / gridStep) * gridStep;

      if (newWidth !== props.width) {
        emit('update:width', newWidth);
      }
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      emit('resizeEnd'); // 通知父组件结束调整大小
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const fetchData = async () => {
    if (!props.query) return;
    loading.value = true;
    error.value = '';
    try {
      const res = await queryLogs({
        query: props.query,
        limit: 2000,
        range: props.range || '24h',
      });
      const responseData = res.data as any;
      chartData.value = responseData?.data?.result || [];
    } catch (err) {
      error.value = t('log.dashboard.custom.message.load.fail');
    } finally {
      loading.value = false;
    }
  };

  // 用于将原始值（如 LOGIN_SUCCESS）翻译成显示文本（如“登录成功”）
  const i18nMap = computed(() => {
    const map = new Map<string, string>();
    if (!props.allOptions) return map;

    // 遍历 allOptions 中的每个列表并添加到映射中
    props.allOptions.modules.forEach((item) => map.set(item.value, item.label));
    props.allOptions.actions.forEach((item) => map.set(item.value, item.label));
    props.allOptions.traceabilityActionTypes.forEach((item) =>
      map.set(item.value, item.label)
    );
    props.allOptions.traceabilityActionSourceTypes.forEach((item) =>
      map.set(item.value, item.label)
    );

    return map;
  });

  // 提取 LogQL 查询中的分组字段（例如 'act', 'mod', 'jobName'）
  const groupByField = computed(() => {
    // 匹配 'by (fieldName)' 或 'topk(N, sum by (fieldName))' 中的 fieldName
    const match = props.query.match(/\bby\s*\(([^)]+)\)/);
    return match ? match[1] : null;
  });

  const chartOption = computed(() => {
    const isPie = props.type === 'pie';
    const isScatter = props.type === 'scatter';
    const isRadar = props.type === 'radar';
    const isFunnel = props.type === 'funnel';
    const isGauge = props.type === 'gauge';
    const isArea = props.type === 'area';

    const series: any[] = [];
    const legendData: string[] = [];

    if (chartData.value.length > 0) {
      const processedData = chartData.value.map((item: any) => {
        // 根据 groupByField 提取原始值，并使用 i18nMap 进行翻译
        const rawValue =
          groupByField.value && item.metric[groupByField.value]
            ? item.metric[groupByField.value]
            : 'Total'; // 如果没有分组字段或值，则默认为 'Total'

        const name = i18nMap.value.get(rawValue) || rawValue; // 尝试翻译，否则使用原始值

        let total = 0;
        const values = item.values.map((val: any[]) => {
          const v = parseFloat(val[1]);
          total += v;
          let ts = parseInt(val[0], 10);
          if (ts < 10000000000) {
            ts *= 1000;
          }
          return [ts, v];
        });

        return { name, values, total };
      });

      if (props.type === 'bar' || isPie || isFunnel) {
        processedData.sort((a: any, b: any) => b.total - a.total);
      }

      if (isPie || isFunnel) {
        const data = processedData.map((item: any) => ({
          value: item.total,
          name: item.name,
        }));
        processedData.forEach((item: any) => legendData.push(item.name));

        series.push({
          name: 'Distribution',
          type: isPie ? 'pie' : 'funnel',
          radius: isPie ? ['40%', '70%'] : undefined,
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#fff',
            borderWidth: 2,
          },
          label: {
            show: isFunnel,
            position: isPie ? 'center' : 'inside',
          },
          emphasis: {
            label: {
              show: true,
              fontSize: '20',
              fontWeight: 'bold',
            },
          },
          labelLine: {
            show: false,
          },
          data,
        });
      } else if (isRadar) {
        // Radar chart logic (simplified)
        const indicators = processedData.map((item: any) => ({
          name: item.name,
          max: Math.max(...processedData.map((d: any) => d.total)) * 1.2,
        }));
        const data = processedData.map((item: any) => item.total);

        series.push({
          type: 'radar',
          data: [
            {
              value: data,
              name: 'Data',
            },
          ],
        });
        return {
          radar: {
            indicator: indicators,
          },
          series,
        };
      } else if (isGauge) {
        // Gauge chart logic (simplified, takes first item)
        if (processedData.length > 0) {
          const item = processedData[0];
          series.push({
            type: 'gauge',
            data: [
              {
                value: item.total,
                name: item.name,
              },
            ],
          });
        }
      } else {
        processedData.forEach((item: any) => {
          legendData.push(item.name);

          let chartType = props.type || 'line';
          if (isScatter) chartType = 'scatter';
          else if (isArea) chartType = 'line';

          series.push({
            name: item.name,
            type: chartType,
            data: item.values,
            smooth: true,
            showSymbol: isScatter,
            symbolSize: isScatter ? 10 : 4,
            areaStyle: isArea ? { opacity: 0.5 } : undefined,
            stack: props.type === 'bar' ? 'total' : undefined,
          });
        });
      }
    }

    const baseOption = {
      tooltip: {
        trigger: isPie || isFunnel || isGauge ? 'item' : 'axis',
        formatter:
          isPie || isFunnel
            ? '{b}: {c} ({d}%)'
            : (params: any) => {
                let res = '';
                if (params && params.length > 0) {
                  const date = new Date(params[0].value[0]);
                  const year = date.getFullYear();
                  const month = (date.getMonth() + 1)
                    .toString()
                    .padStart(2, '0');
                  const day = date.getDate().toString().padStart(2, '0');
                  const hours = date.getHours().toString().padStart(2, '0');
                  const minutes = date.getMinutes().toString().padStart(2, '0');
                  res += `${year}-${month}-${day} ${hours}:${minutes}<br/>`;
                  params.forEach((item: any) => {
                    res += `${item.marker}${item.seriesName}: ${item.value[1]}<br/>`;
                  });
                }
                return res;
              },
      },
      legend: {
        data: legendData,
        type: 'scroll',
        bottom: 0,
      },
      grid: {
        top: 30,
        left: '3%',
        right: '4%',
        bottom: 30,
        containLabel: true,
      },
    };

    if (isPie || isFunnel || isGauge) {
      return {
        ...baseOption,
        series,
      };
    }

    return {
      ...baseOption,
      xAxis: {
        type: 'time',
        boundaryGap: false,
        axisLabel: {
          formatter: (value: number) => {
            const date = new Date(value);
            const diff =
              chartData.value.length > 0 && chartData.value[0].values.length > 1
                ? chartData.value[0].values[
                    chartData.value[0].values.length - 1
                  ][0] - chartData.value[0].values[0][0]
                : 0;
            const day = 24 * 3600 * 1000;

            if (diff < day) {
              // 1天内，显示 HH:mm
              const hours = date.getHours().toString().padStart(2, '0');
              const minutes = date.getMinutes().toString().padStart(2, '0');
              return `${hours}:${minutes}`;
            }
            if (diff < 30 * day) {
              // 1个月内，显示 MM-dd HH:mm
              const month = (date.getMonth() + 1).toString().padStart(2, '0');
              const d = date.getDate().toString().padStart(2, '0');
              const hours = date.getHours().toString().padStart(2, '0');
              const minutes = date.getMinutes().toString().padStart(2, '0');
              return `${month}-${d} ${hours}:${minutes}`;
            }
            // 超过1个月，显示 yyyy-MM-dd
            const year = date.getFullYear();
            const month = (date.getMonth() + 1).toString().padStart(2, '0');
            const d = date.getDate().toString().padStart(2, '0');
            return `${year}-${month}-${d}`;
          },
        },
      },
      yAxis: {
        type: 'value',
      },
      series,
      animationDuration: 1000,
    };
  });

  onMounted(() => {
    setTimeout(() => {
      fetchData();
    }, 500);
  });

  watch(
    () => props.query,
    () => {
      fetchData();
    }
  );
</script>

<style scoped lang="less">
  .log-chart-wrapper {
    position: relative;
    padding: 8px;
    transition: height 0.1s;
    box-sizing: border-box;
  }

  .log-chart-card {
    height: 100%;
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    background-color: var(--color-bg-2); /* 确保背景色与页面背景区分 */
    border: 1px solid var(--color-border-2); /* 添加边框以区分 */

    :deep(.arco-card-body) {
      flex: 1;
      padding: 10px;
      overflow: hidden;
    }
  }

  .chart-header {
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    height: 24px;
  }

  .chart-title {
    font-weight: 500;
    font-size: 16px;
  }

  .chart-container {
    width: 100%;
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .chart {
    height: 100%;
    width: 100%;
  }

  .resize-handle {
    position: absolute;
    bottom: 10px;
    right: 10px;
    cursor: nwse-resize;
    color: var(--color-text-3);
    z-index: 10;
    padding: 2px;
    background: rgba(255, 255, 255, 0.5);
    border-radius: 4px;

    &:hover {
      color: rgb(var(--primary-6));
      background: var(--color-fill-2);
    }
  }
</style>
