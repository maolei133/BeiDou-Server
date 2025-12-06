<template>
  <div class="config-container">
    <a-spin :loading="loading" style="width: 100%">
      <a-row :gutter="16">
        <a-col :span="12">
          <a-card :title="$t('logs.config.system.title')">
            <a-form :model="logConfig" layout="vertical">
              <a-form-item :label="$t('logs.config.system.enabled')">
                <a-switch v-model="logConfig.enabled" />
              </a-form-item>
              <a-form-item :label="$t('logs.config.system.retentionDays')">
                <a-input-number
                  v-model="logConfig.logRetentionDays"
                  :min="1"
                  :max="365"
                  style="width: 100%"
                />
              </a-form-item>
              <a-form-item :label="$t('logs.config.system.compressionEnabled')">
                <a-switch v-model="logConfig.compressionEnabled" />
              </a-form-item>
              <a-form-item :label="$t('logs.config.system.compressionFormat')">
                <a-input v-model="logConfig.compressionFormat" disabled />
              </a-form-item>
              <a-form-item
                :label="$t('logs.config.system.asyncThreadPoolSize')"
              >
                <a-input-number
                  v-model="logConfig.asyncThreadPoolSize"
                  :min="1"
                  :max="32"
                  style="width: 100%"
                />
              </a-form-item>
              <a-form-item>
                <a-space>
                  <a-button type="primary" @click="handleSaveLogConfig">
                    {{ $t('logs.config.system.save') }}
                  </a-button>
                  <a-button @click="loadLogConfig">
                    {{ $t('logs.config.system.reload') }}
                  </a-button>
                </a-space>
              </a-form-item>
            </a-form>
          </a-card>
        </a-col>

        <a-col :span="12">
          <a-card :title="$t('logs.config.packet.title')">
            <a-form :model="packetConfig" layout="vertical">
              <a-form-item :label="$t('logs.config.packet.inPacketLogEnabled')">
                <a-switch v-model="packetConfig.logIncoming" />
              </a-form-item>
              <a-form-item
                :label="$t('logs.config.packet.outPacketLogEnabled')"
              >
                <a-switch v-model="packetConfig.logOutgoing" />
              </a-form-item>

              <a-divider />

              <a-form-item :label="$t('logs.config.packet.inPacketBlocklist')">
                <a-space direction="vertical" style="width: 100%">
                  <a-tag
                    v-for="opcode in packetConfig.inBlockList"
                    :key="opcode"
                    closable
                    @close="handleRemoveInBlock(opcode)"
                  >
                    {{ opcode }}
                  </a-tag>
                  <a-input-group style="display: flex">
                    <a-input-number
                      v-model="newInOpcode"
                      :min="0"
                      :max="65535"
                      :placeholder="$t('logs.config.packet.opcodeInput')"
                      style="flex: 1"
                    />
                    <a-button type="primary" @click="handleAddInBlock">
                      {{ $t('logs.config.packet.addBlock') }}
                    </a-button>
                  </a-input-group>
                </a-space>
              </a-form-item>

              <a-form-item :label="$t('logs.config.packet.outPacketBlocklist')">
                <a-space direction="vertical" style="width: 100%">
                  <a-tag
                    v-for="opcode in packetConfig.outBlockList"
                    :key="opcode"
                    closable
                    @close="handleRemoveOutBlock(opcode)"
                  >
                    {{ opcode }}
                  </a-tag>
                  <a-input-group style="display: flex">
                    <a-input-number
                      v-model="newOutOpcode"
                      :min="0"
                      :max="65535"
                      :placeholder="$t('logs.config.packet.opcodeInput')"
                      style="flex: 1"
                    />
                    <a-button type="primary" @click="handleAddOutBlock">
                      {{ $t('logs.config.packet.addBlock') }}
                    </a-button>
                  </a-input-group>
                </a-space>
              </a-form-item>
            </a-form>
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
  </div>
</template>

<script lang="ts">
  import { defineComponent, ref, reactive, onMounted } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import {
    configApi,
    type LogConfig,
    type PacketLogConfig,
  } from '@/api/logsystem';

  export default defineComponent({
    name: 'LogConfig',
    setup() {
      const { t } = useI18n();
      const loading = ref(false);
      const newInOpcode = ref<number>();
      const newOutOpcode = ref<number>();

      const logConfig = reactive<LogConfig>({
        enabled: true,
        logDir: '',
        logRetentionDays: 30,
        maxLogFileSize: 0,
        compressionEnabled: false,
        compressionFormat: 'gzip',
        highFreqBufferSize: 0,
        highFreqFlushInterval: 0,
        mediumFreqBufferSize: 0,
        mediumFreqFlushInterval: 0,
        lowFreqBufferSize: 0,
        asyncThreadPoolSize: 4,
        asyncQueueSize: 0,
      });

      const packetConfig = reactive<PacketLogConfig>({
        enabled: false,
        logOutgoing: false,
        logIncoming: false,
        inBlockList: [],
        outBlockList: [],
        inBlockListSize: 0,
        outBlockListSize: 0,
      });

      const loadLogConfig = async () => {
        loading.value = true;
        try {
          const response = await configApi.getLogConfig();
          if (response && response.data) {
            Object.assign(logConfig, response.data);
            Message.success(t('logs.config.system.loadSuccess'));
          }
        } catch (error) {
          Message.error(t('logs.config.system.loadFailed'));
          console.error('加载日志配置失败:', error);
        } finally {
          loading.value = false;
        }
      };

      const loadPacketConfig = async () => {
        loading.value = true;
        try {
          const response = await configApi.getPacketConfig();
          if (response && response.data) {
            Object.assign(packetConfig, response.data);
            Message.success(t('logs.config.packet.loadSuccess'));
          }
        } catch (error) {
          Message.error(t('logs.config.packet.loadFailed'));
          console.error('加载网络包配置失败:', error);
        } finally {
          loading.value = false;
        }
      };

      const handleSaveLogConfig = async () => {
        try {
          await configApi.updateLogConfig(logConfig);
          Message.success(t('logs.config.system.saveSuccess'));
        } catch (error) {
          Message.error(t('logs.config.system.saveFailed'));
          console.error('保存日志配置失败:', error);
        }
      };

      const handleAddInBlock = async () => {
        if (newInOpcode.value === undefined) {
          Message.warning(t('logs.config.packet.inputOpcodeWarning'));
          return;
        }
        try {
          await configApi.addInBlockPacket(newInOpcode.value);
          packetConfig.inBlockList.push(newInOpcode.value);
          newInOpcode.value = undefined;
          Message.success(t('logs.config.packet.addBlockSuccess'));
        } catch (error) {
          Message.error(t('logs.config.packet.addBlockFailed'));
          console.error('添加入站包屏蔽失败:', error);
        }
      };

      const handleRemoveInBlock = async (opcode: number) => {
        try {
          await configApi.deleteInBlockPacket(opcode);
          const index = packetConfig.inBlockList.indexOf(opcode);
          if (index > -1) {
            packetConfig.inBlockList.splice(index, 1);
          }
          Message.success(t('logs.config.packet.removeBlockSuccess'));
        } catch (error) {
          Message.error(t('logs.config.packet.removeBlockFailed'));
          console.error('移除入站包屏蔽失败:', error);
        }
      };

      const handleAddOutBlock = async () => {
        if (newOutOpcode.value === undefined) {
          Message.warning(t('logs.config.packet.inputOpcodeWarning'));
          return;
        }
        try {
          await configApi.addOutBlockPacket(newOutOpcode.value);
          packetConfig.outBlockList.push(newOutOpcode.value);
          newOutOpcode.value = undefined;
          Message.success(t('logs.config.packet.addBlockSuccess'));
        } catch (error) {
          Message.error(t('logs.config.packet.addBlockFailed'));
          console.error('添加出站包屏蔽失败:', error);
        }
      };

      const handleRemoveOutBlock = async (opcode: number) => {
        try {
          await configApi.deleteOutBlockPacket(opcode);
          const index = packetConfig.outBlockList.indexOf(opcode);
          if (index > -1) {
            packetConfig.outBlockList.splice(index, 1);
          }
          Message.success(t('logs.config.packet.removeBlockSuccess'));
        } catch (error) {
          Message.error(t('logs.config.packet.removeBlockFailed'));
          console.error('移除出站包屏蔽失败:', error);
        }
      };

      onMounted(() => {
        loadLogConfig();
        loadPacketConfig();
      });

      return {
        loading,
        logConfig,
        packetConfig,
        newInOpcode,
        newOutOpcode,
        loadLogConfig,
        handleSaveLogConfig,
        handleAddInBlock,
        handleRemoveInBlock,
        handleAddOutBlock,
        handleRemoveOutBlock,
      };
    },
  });
</script>

<style scoped lang="less">
  .config-container {
    padding: 16px;

    :deep(.arco-card) {
      margin-bottom: 16px;
    }

    :deep(.arco-tag) {
      margin: 4px;
    }
  }
</style>
