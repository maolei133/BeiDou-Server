<template>
  <div class="container">
    <a-card class="general-card" title="快递配置">
      <template #extra>
        <a-tag v-if="configLoaded" color="green">配置已加载</a-tag>
        <a-tag v-else color="red">配置未加载</a-tag>
      </template>
      <a-spin :loading="loading" style="width: 100%">
        <div v-if="!configLoaded && !loading" class="error-container">
          <a-empty description="未加载到快递配置数据，请检查数据库或网络连接" />
          <a-button type="primary" @click="fetchData">重试</a-button>
        </div>
        <a-form
          v-else
          ref="formRef"
          :model="formModel"
          :label-col-props="{ span: 8 }"
          :wrapper-col-props="{ span: 16 }"
          style="max-width: 600px; margin: 0 auto"
        >
          <a-form-item
            field="use_duey"
            label="启用快递系统"
            help="是否开启整个快递系统功能"
          >
            <a-switch v-model="formModel.use_duey" />
          </a-form-item>
          <a-form-item
            field="minimum_gm_level_to_use_duey"
            label="GM使用限制等级"
            help="GM账号使用快递功能的最低等级要求"
          >
            <a-input-number
              v-model="formModel.minimum_gm_level_to_use_duey"
              :min="0"
              :max="6"
            />
          </a-form-item>
          <a-form-item
            field="enable_duey_quick_delivery"
            label="启用快速配送"
            help="是否允许玩家使用快速配送服务"
          >
            <a-switch v-model="formModel.enable_duey_quick_delivery" />
          </a-form-item>
          <a-form-item
            field="enable_duey_normal_delivery"
            label="启用普通配送"
            help="是否允许玩家使用普通配送服务"
          >
            <a-switch v-model="formModel.enable_duey_normal_delivery" />
          </a-form-item>
          <a-form-item
            field="duey_min_level"
            label="最低使用等级"
            help="玩家使用快递服务的最低等级限制"
          >
            <a-input-number
              v-model="formModel.duey_min_level"
              :min="1"
              :max="255"
            />
          </a-form-item>
          <a-form-item
            field="duey_expire_time"
            label="过期时间"
            help="快递包裹在未领取情况下的过期时间"
          >
            <div style="display: flex; gap: 8px; align-items: center">
              <a-input-number
                v-model="expireTimeDays"
                :min="0"
                style="width: 80px"
                placeholder="天"
                @change="updateExpireTimeFromComponents"
              >
                <template #suffix>天</template>
              </a-input-number>
              <a-select
                v-model="expireTimeHours"
                style="width: 80px"
                placeholder="时"
                @change="updateExpireTimeFromComponents"
              >
                <a-option v-for="h in hoursOptions" :key="h" :value="h">
                  {{ h }}
                </a-option>
                <template #trigger-icon>
                  <span style="margin-right: 8px">时</span>
                </template>
              </a-select>
              <a-select
                v-model="expireTimeMinutes"
                style="width: 80px"
                placeholder="分"
                @change="updateExpireTimeFromComponents"
              >
                <a-option v-for="m in minutesOptions" :key="m" :value="m">
                  {{ m }}
                </a-option>
                <template #trigger-icon>
                  <span style="margin-right: 8px">分</span>
                </template>
              </a-select>
              <span style="color: var(--color-text-3); margin-left: 8px">
                (共 {{ formModel.duey_expire_time }} 分钟)
              </span>
            </div>
          </a-form-item>
          <a-form-item
            field="duey_normal_delivery_time"
            label="普通配送耗时"
            help="普通快递送达所需时间"
          >
            <div style="display: flex; gap: 8px; align-items: center">
              <a-input-number
                v-model="deliveryTimeDays"
                :min="0"
                style="width: 80px"
                placeholder="天"
                @change="updateDeliveryTimeFromComponents"
              >
                <template #suffix>天</template>
              </a-input-number>
              <a-select
                v-model="deliveryTimeHours"
                style="width: 80px"
                placeholder="时"
                @change="updateDeliveryTimeFromComponents"
              >
                <a-option v-for="h in hoursOptions" :key="h" :value="h">
                  {{ h }}
                </a-option>
                <template #trigger-icon>
                  <span style="margin-right: 8px">时</span>
                </template>
              </a-select>
              <a-select
                v-model="deliveryTimeMinutes"
                style="width: 80px"
                placeholder="分"
                @change="updateDeliveryTimeFromComponents"
              >
                <a-option v-for="m in minutesOptions" :key="m" :value="m">
                  {{ m }}
                </a-option>
                <template #trigger-icon>
                  <span style="margin-right: 8px">分</span>
                </template>
              </a-select>
              <span style="color: var(--color-text-3); margin-left: 8px">
                (共 {{ formModel.duey_normal_delivery_time }} 分钟)
              </span>
            </div>
          </a-form-item>
          <a-form-item
            field="duey_retention_days"
            label="记录保留天数"
            help="已过期、已领取、已删除的快递记录保留天数，默认30天"
          >
            <a-input-number
              v-model="formModel.duey_retention_days"
              :min="1"
              :max="365"
            >
              <template #suffix>天</template>
            </a-input-number>
          </a-form-item>
          <a-form-item
            field="duey_normal_fee"
            label="普通快递费用"
            help="发送普通快递所需的基础金币费用，默认5000"
          >
            <a-input-number
              v-model="formModel.duey_normal_fee"
              :min="0"
              :step="100"
            />
          </a-form-item>
          <a-form-item>
            <a-space>
              <a-button type="primary" @click="handleSubmit">保存配置</a-button>
              <a-button @click="fetchData">重置</a-button>
            </a-space>
          </a-form-item>
        </a-form>

        <a-divider />
      </a-spin>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, reactive, onMounted } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import { getConfigList, batchUpdateConfig, ConfigResult } from '@/api/config';

  const { loading, setLoading } = useLoading(true);
  const formRef = ref();
  const configLoaded = ref(false);
  const formModel = reactive<Record<string, any>>({
    use_duey: true,
    minimum_gm_level_to_use_duey: 4,
    enable_duey_quick_delivery: true,
    enable_duey_normal_delivery: true,
    duey_min_level: 10,
    duey_expire_time: 43200, // 30 days in minutes
    duey_normal_delivery_time: 1440, // 1 day in minutes
    duey_retention_days: 30,
    duey_normal_fee: 5000,
  });

  // Temporary state for time inputs (Days, Hours, Minutes)
  const expireTimeDays = ref(0);
  const expireTimeHours = ref(0);
  const expireTimeMinutes = ref(0);

  const deliveryTimeDays = ref(0);
  const deliveryTimeHours = ref(0);
  const deliveryTimeMinutes = ref(0);

  const hoursOptions = Array.from({ length: 24 }, (_, i) => i);
  const minutesOptions = Array.from({ length: 60 }, (_, i) => i);

  // Map config keys to form model keys
  const configKeys = [
    'use_duey',
    'minimum_gm_level_to_use_duey',
    'enable_duey_quick_delivery',
    'enable_duey_normal_delivery',
    'duey_min_level',
    'duey_expire_time',
    'duey_normal_delivery_time',
    'duey_retention_days',
    'duey_normal_fee',
  ];

  const originalConfigs = ref<ConfigResult[]>([]);

  const updateExpireTimeFromComponents = () => {
    const totalMinutes =
      (expireTimeDays.value || 0) * 24 * 60 +
      (expireTimeHours.value || 0) * 60 +
      (expireTimeMinutes.value || 0);
    formModel.duey_expire_time = totalMinutes;
  };

  const updateDeliveryTimeFromComponents = () => {
    const totalMinutes =
      (deliveryTimeDays.value || 0) * 24 * 60 +
      (deliveryTimeHours.value || 0) * 60 +
      (deliveryTimeMinutes.value || 0);
    formModel.duey_normal_delivery_time = totalMinutes;
  };

  const initTimeInputs = () => {
    // Initialize expire time inputs
    let minutes = Number(formModel.duey_expire_time) || 0;
    expireTimeDays.value = Math.floor(minutes / (24 * 60));
    minutes %= 24 * 60;
    expireTimeHours.value = Math.floor(minutes / 60);
    expireTimeMinutes.value = minutes % 60;

    // Initialize delivery time inputs
    minutes = Number(formModel.duey_normal_delivery_time) || 0;
    deliveryTimeDays.value = Math.floor(minutes / (24 * 60));
    minutes %= 24 * 60;
    deliveryTimeHours.value = Math.floor(minutes / 60);
    deliveryTimeMinutes.value = minutes % 60;
  };

  // Helper to handle potential field name differences (camelCase vs snake_case)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getConfigCode = (item: any) => item.configCode || item.config_code;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getConfigValue = (item: any) => item.configValue || item.config_value;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getConfigClazz = (item: any) => item.configClazz || item.config_clazz;

  const fetchData = async () => {
    setLoading(true);
    configLoaded.value = false;
    try {
      // Fetch all configs and filter duey related ones
      const res = await getConfigList({
        pageNo: 1,
        pageSize: 1000,
        type: 'server',
        filter: 'duey',
      });

      // Handle different response structures (AxiosResponse vs direct data)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const records =
        (res as any).data?.data?.records || (res as any).data?.records || [];

      // Store all records to ensure we can find them later
      originalConfigs.value = records;

      // Check if we found any related configs
      const foundConfigs = originalConfigs.value.filter((item: ConfigResult) =>
        configKeys.includes(getConfigCode(item))
      );

      if (foundConfigs.length === 0) {
        Message.warning('未加载到快递相关配置，请检查数据库或网络连接');
        // 如果加载失败，表单对应的参数值设为空值
        configKeys.forEach((key) => {
          formModel[key] = null;
        });
      } else {
        configLoaded.value = true;
        Message.success('配置加载成功');
      }

      foundConfigs.forEach((config: ConfigResult) => {
        const code = getConfigCode(config);
        const value = getConfigValue(config);
        const clazz = getConfigClazz(config);

        if (clazz === 'java.lang.Boolean') {
          formModel[code] = value === 'true';
        } else if (
          clazz === 'java.lang.Integer' ||
          clazz === 'java.lang.Long'
        ) {
          let numValue = Number(value);
          // Handle time fields that might be in milliseconds
          if (
            (code === 'duey_expire_time' ||
              code === 'duey_normal_delivery_time') &&
            numValue > 10000000 // Heuristic: if value is very large, assume milliseconds
          ) {
            numValue = Math.floor(numValue / 60000); // Convert ms to minutes
          }
          formModel[code] = numValue;
        } else {
          formModel[code] = value;
        }
      });
    } catch (err) {
      // console.error(err);
      Message.error('加载配置失败');
      // 如果加载失败，表单对应的参数值设为空值
      configKeys.forEach((key) => {
        formModel[key] = null;
      });
    } finally {
      initTimeInputs();
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      if (!configLoaded.value) {
        Message.error('配置数据未加载，无法保存。请尝试刷新页面。');
        // Try to fetch again
        await fetchData();
        if (!configLoaded.value) {
          setLoading(false);
          return;
        }
      }

      const updates: ConfigResult[] = [];
      const missingKeys = [];

      // eslint-disable-next-line no-restricted-syntax
      for (const key of configKeys) {
        const original = originalConfigs.value.find(
          (c) => getConfigCode(c) === key
        );
        if (!original) {
          missingKeys.push(key);
          // eslint-disable-next-line no-continue
          continue;
        }

        let newValue = formModel[key];

        // Convert minutes back to milliseconds for time fields if original was Long/Large
        if (key === 'duey_expire_time' || key === 'duey_normal_delivery_time') {
          const originalVal = Number(getConfigValue(original));
          // If original was large (ms) or clazz is Long, save as ms
          if (
            originalVal > 10000000 ||
            getConfigClazz(original) === 'java.lang.Long'
          ) {
            newValue *= 60000;
          }
        }

        newValue = String(newValue);
        const originalValue = getConfigValue(original);

        if (newValue !== originalValue) {
          updates.push({
            ...original,
            configValue: newValue,
          });
        }
      }

      if (updates.length > 0) {
        await batchUpdateConfig(updates);
        Message.success('配置保存成功');
        await fetchData();
      } else if (missingKeys.length > 0) {
        Message.warning(
          `未找到以下配置项，无法更新: ${missingKeys.join(', ')}`
        );
      } else {
        Message.info('没有配置需要更新');
      }
    } catch (err) {
      Message.error('保存配置失败');
    } finally {
      setLoading(false);
    }
  };

  onMounted(() => {
    initTimeInputs();
    fetchData();
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
  }
  .footer-note {
    color: var(--color-text-3);
    font-size: 12px;
    text-align: center;
  }
  .error-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px;
    gap: 16px;
  }
</style>
