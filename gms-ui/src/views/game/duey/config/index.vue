<template>
  <div class="container">
    <a-card class="general-card" title="快递配置">
      <a-spin :loading="loading" style="width: 100%">
        <a-form
          ref="formRef"
          :model="formModel"
          :label-col-props="{ span: 8 }"
          :wrapper-col-props="{ span: 16 }"
          style="max-width: 600px; margin: 0 auto"
        >
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
            label="过期时间 (毫秒)"
            help="快递包裹在未领取情况下的过期时间，默认30天 (2592000000ms)"
          >
            <a-input-number
              v-model="formModel.duey_expire_time"
              :min="0"
              :step="1000"
            />
          </a-form-item>
          <a-form-item
            field="duey_normal_delivery_time"
            label="普通配送耗时 (毫秒)"
            help="普通快递送达所需时间，默认1天 (86400000ms)"
          >
            <a-input-number
              v-model="formModel.duey_normal_delivery_time"
              :min="0"
              :step="1000"
            />
          </a-form-item>
          <a-form-item>
            <a-space>
              <a-button type="primary" @click="handleSubmit">保存配置</a-button>
              <a-button @click="fetchData">重置</a-button>
            </a-space>
          </a-form-item>
        </a-form>
      </a-spin>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, reactive, onMounted } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import { getConfigList, updateConfig, ConfigResult } from '@/api/config';

  const { loading, setLoading } = useLoading(true);
  const formRef = ref();
  const formModel = reactive<Record<string, any>>({
    enable_duey_quick_delivery: true,
    enable_duey_normal_delivery: true,
    duey_min_level: 10,
    duey_expire_time: 2592000000,
    duey_normal_delivery_time: 86400000,
  });

  // Map config keys to form model keys
  const configKeys = [
    'enable_duey_quick_delivery',
    'enable_duey_normal_delivery',
    'duey_min_level',
    'duey_expire_time',
    'duey_normal_delivery_time',
  ];

  const originalConfigs = ref<ConfigResult[]>([]);

  const fetchData = async () => {
    setLoading(true);
    try {
      // Fetch all configs and filter duey related ones
      // Ideally backend should support filtering by prefix or type
      const { data } = await getConfigList({
        pageNo: 1,
        pageSize: 1000,
        type: '',
        subType: '',
        filter: '',
      });
      const configs = data.data.records.filter((item: ConfigResult) =>
        configKeys.includes(item.configCode)
      );
      originalConfigs.value = configs;

      configs.forEach((config: ConfigResult) => {
        if (config.configClazz === 'java.lang.Boolean') {
          formModel[config.configCode] = config.configValue === 'true';
        } else if (
          config.configClazz === 'java.lang.Integer' ||
          config.configClazz === 'java.lang.Long'
        ) {
          formModel[config.configCode] = Number(config.configValue);
        } else {
          formModel[config.configCode] = config.configValue;
        }
      });
    } catch (err) {
      // err
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      const updates = [];
      // Use for...of loop instead of forEach to support await inside loop if needed,
      // or map to promises. Here we are building an array of promises.
      // However, the linter error was about restricted syntax (iterators/generators) which usually flags for..of loops if configured strictly,
      // OR it might be flagging something else.
      // The error message "iterators/generators require regenerator-runtime... Separately, loops should be avoided in favor of array iterations"
      // suggests avoiding for..of. Let's use Promise.all with map.

      const updatePromises = configKeys
        .map((key) => {
          const original = originalConfigs.value.find(
            (c) => c.configCode === key
          );
          if (original) {
            const newValue = String(formModel[key]);
            if (newValue !== original.configValue) {
              return updateConfig({
                ...original,
                configValue: newValue,
              });
            }
          }
          return null;
        })
        .filter((p) => p !== null);

      if (updatePromises.length > 0) {
        await Promise.all(updatePromises);
        Message.success('配置保存成功');
        await fetchData();
      } else {
        Message.info('没有配置需要更新');
      }
    } catch (err) {
      // err
    } finally {
      setLoading(false);
    }
  };

  onMounted(() => {
    fetchData();
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
  }
</style>
