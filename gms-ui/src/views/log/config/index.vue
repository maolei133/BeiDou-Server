<template>
  <div class="container">
    <Breadcrumb :items="['menu.log', 'menu.log.config']" />

    <a-tabs default-active-key="business" type="rounded">
      <!-- Tab 1: 业务配置 -->
      <a-tab-pane key="business" :title="$t('log.config.tab.business')">
        <a-space direction="vertical" :size="16" style="width: 100%">
          <!-- 模块开关 -->
          <a-card class="general-card" :title="$t('log.config.module.title')">
            <a-spin :loading="loadingModules">
              <a-space wrap>
                <div
                  v-for="mod in moduleList"
                  :key="mod.value"
                  class="module-item"
                >
                  <span class="module-name">{{ mod.label }}</span>
                  <a-switch
                    :model-value="moduleSwitches[mod.value]"
                    @change="
                      (val) => handleToggleModule(mod.value, val as boolean)
                    "
                  >
                    <template #checked>{{
                      $t('log.config.switch.on')
                    }}</template>
                    <template #unchecked>{{
                      $t('log.config.switch.off')
                    }}</template>
                  </a-switch>
                </div>
                <div
                  v-if="Object.keys(moduleList).length === 0"
                  class="empty-tip"
                >
                  {{ $t('log.config.module.empty') }}
                </div>
              </a-space>
            </a-spin>
          </a-card>

          <!-- 日志级别 -->
          <a-card class="general-card" :title="$t('log.config.level.title')">
            <a-spin :loading="loadingLevels">
              <a-table :data="levelsData" :pagination="false">
                <template #columns>
                  <a-table-column
                    :title="$t('log.config.level.name')"
                    data-index="name"
                  />
                  <a-table-column
                    :title="$t('log.config.level.current')"
                    data-index="level"
                  >
                    <template #cell="{ record }">
                      <a-tag :color="getLevelColor(record.level)">{{
                        record.level
                      }}</a-tag>
                    </template>
                  </a-table-column>
                  <a-table-column :title="$t('log.config.level.action')">
                    <template #cell="{ record }">
                      <a-select
                        :model-value="record.level"
                        style="width: 120px"
                        @change="
                          (val) => handleChangeLevel(record.name, val as string)
                        "
                      >
                        <a-option
                          v-for="level in logLevels"
                          :key="level"
                          :value="level"
                          >{{ level }}</a-option
                        >
                      </a-select>
                    </template>
                  </a-table-column>
                </template>
              </a-table>
            </a-spin>
          </a-card>
        </a-space>
      </a-tab-pane>

      <!-- Tab 2: 高级配置 -->
      <a-tab-pane key="advanced" :title="$t('log.config.tab.advanced')">
        <a-space direction="vertical" :size="16" style="width: 100%">
          <a-alert type="warning" show-icon>
            {{ $t('log.config.advanced.warning') }}
          </a-alert>

          <!-- Loki 配置 -->
          <a-card class="general-card" :title="$t('log.config.loki.title')">
            <template #extra>
              <a-space>
                <a-button @click="fetchLokiConfig">
                  <template #icon><icon-refresh /></template>
                  {{ $t('log.config.action.refresh') }}
                </a-button>
                <a-button
                  type="primary"
                  status="success"
                  :loading="savingLoki"
                  @click="saveLokiConfig"
                >
                  <template #icon><icon-save /></template>
                  {{ $t('log.config.action.save') }}
                </a-button>
              </a-space>
            </template>
            <a-spin :loading="loadingLoki">
              <a-form :model="lokiForm" layout="vertical">
                <a-collapse :default-active-keys="['server', 'retention']">
                  <!-- Server Config -->
                  <a-collapse-item
                    key="server"
                    :header="$t('log.config.section.server')"
                  >
                    <a-row :gutter="16">
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.http_port')"
                          field="server.http_listen_port"
                        >
                          <a-input-number
                            v-model="lokiForm.server.http_listen_port"
                          />
                        </a-form-item>
                      </a-col>
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.grpc_port')"
                          field="server.grpc_listen_port"
                        >
                          <a-input-number
                            v-model="lokiForm.server.grpc_listen_port"
                          />
                        </a-form-item>
                      </a-col>
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.auth_enabled')"
                          field="auth_enabled"
                        >
                          <a-switch v-model="lokiForm.auth_enabled" />
                        </a-form-item>
                      </a-col>
                    </a-row>
                  </a-collapse-item>

                  <!-- Retention & Compaction -->
                  <a-collapse-item
                    key="retention"
                    :header="$t('log.config.section.retention')"
                  >
                    <a-row :gutter="16">
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.retention_period')"
                          field="limits_config.retention_period"
                        >
                          <a-input
                            v-model="lokiForm.limits_config.retention_period"
                            :placeholder="
                              $t('log.config.placeholder.retention')
                            "
                          />
                          <template #help>{{
                            $t('log.config.loki.retention.help')
                          }}</template>
                        </a-form-item>
                      </a-col>
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.compaction_enabled')"
                          field="compactor.retention_enabled"
                        >
                          <a-switch
                            v-model="lokiForm.compactor.retention_enabled"
                          />
                        </a-form-item>
                      </a-col>
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.loki.compaction_interval')"
                          field="compactor.compaction_interval"
                        >
                          <a-input
                            v-model="lokiForm.compactor.compaction_interval"
                            :placeholder="
                              $t('log.config.placeholder.compaction')
                            "
                          />
                        </a-form-item>
                      </a-col>
                    </a-row>
                    <a-row :gutter="16">
                      <a-col :span="12">
                        <a-form-item
                          :label="$t('log.config.loki.compactor_dir')"
                          field="compactor.working_directory"
                        >
                          <a-input
                            v-model="lokiForm.compactor.working_directory"
                          />
                        </a-form-item>
                      </a-col>
                    </a-row>
                  </a-collapse-item>

                  <!-- Limits -->
                  <a-collapse-item
                    key="limits"
                    :header="$t('log.config.section.limits')"
                  >
                    <a-row :gutter="16">
                      <a-col :span="12">
                        <a-form-item
                          :label="$t('log.config.loki.max_entries')"
                          field="limits_config.max_entries_limit_per_query"
                        >
                          <a-input-number
                            v-model="
                              lokiForm.limits_config.max_entries_limit_per_query
                            "
                          />
                        </a-form-item>
                      </a-col>
                    </a-row>
                  </a-collapse-item>

                  <!-- Storage -->
                  <a-collapse-item
                    key="storage"
                    :header="$t('log.config.section.storage')"
                  >
                    <a-row :gutter="16">
                      <a-col :span="12">
                        <a-form-item
                          :label="$t('log.config.loki.chunks_dir')"
                          field="common.storage.filesystem.chunks_directory"
                        >
                          <a-input
                            v-model="
                              lokiForm.common.storage.filesystem
                                .chunks_directory
                            "
                          />
                        </a-form-item>
                      </a-col>
                      <a-col :span="12">
                        <a-form-item
                          :label="$t('log.config.loki.rules_dir')"
                          field="common.storage.filesystem.rules_directory"
                        >
                          <a-input
                            v-model="
                              lokiForm.common.storage.filesystem.rules_directory
                            "
                          />
                        </a-form-item>
                      </a-col>
                    </a-row>
                  </a-collapse-item>
                </a-collapse>
              </a-form>
            </a-spin>
          </a-card>

          <!-- Promtail 配置 -->
          <a-card class="general-card" :title="$t('log.config.promtail.title')">
            <template #extra>
              <a-space>
                <a-button @click="fetchPromtailConfig">
                  <template #icon><icon-refresh /></template>
                  {{ $t('log.config.action.refresh') }}
                </a-button>
                <a-button
                  type="primary"
                  status="success"
                  :loading="savingPromtail"
                  @click="savePromtailConfig"
                >
                  <template #icon><icon-save /></template>
                  {{ $t('log.config.action.save') }}
                </a-button>
              </a-space>
            </template>
            <a-spin :loading="loadingPromtail">
              <a-form :model="promtailForm" layout="vertical">
                <a-collapse :default-active-keys="['server', 'scrape']">
                  <!-- Server Config -->
                  <a-collapse-item
                    key="server"
                    :header="$t('log.config.section.server')"
                  >
                    <a-row :gutter="16">
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.promtail.http_port')"
                          field="server.http_listen_port"
                        >
                          <a-input-number
                            v-model="promtailForm.server.http_listen_port"
                          />
                        </a-form-item>
                      </a-col>
                      <a-col :span="8">
                        <a-form-item
                          :label="$t('log.config.promtail.grpc_port')"
                          field="server.grpc_listen_port"
                        >
                          <a-input-number
                            v-model="promtailForm.server.grpc_listen_port"
                          />
                        </a-form-item>
                      </a-col>
                    </a-row>
                  </a-collapse-item>

                  <!-- Clients -->
                  <a-collapse-item
                    key="clients"
                    :header="$t('log.config.section.clients')"
                  >
                    <div
                      v-for="(client, index) in promtailForm.clients"
                      :key="index"
                      style="margin-bottom: 10px"
                    >
                      <a-row :gutter="16">
                        <a-col :span="20">
                          <a-form-item
                            :label="$t('log.config.promtail.loki_url')"
                            :field="`clients.${index}.url`"
                          >
                            <a-input v-model="client.url" />
                          </a-form-item>
                        </a-col>
                      </a-row>
                    </div>
                  </a-collapse-item>

                  <!-- Scrape Configs -->
                  <a-collapse-item
                    key="scrape"
                    :header="$t('log.config.section.scrape')"
                  >
                    <a-space direction="vertical" style="width: 100%">
                      <a-card
                        v-for="(job, index) in promtailForm.scrape_configs"
                        :key="index"
                        class="job-card"
                      >
                        <template #title>
                          <span style="font-weight: bold"
                            >{{ $t('log.config.job.title') }}:
                            {{ job.job_name }}</span
                          >
                        </template>
                        <template #extra>
                          <a-button
                            status="danger"
                            size="mini"
                            @click="removeScrapeJob(index)"
                          >
                            <template #icon><icon-delete /></template>
                          </a-button>
                        </template>

                        <a-row :gutter="16">
                          <a-col :span="8">
                            <a-form-item
                              :label="$t('log.config.promtail.job_name')"
                              :field="`scrape_configs.${index}.job_name`"
                            >
                              <a-input v-model="job.job_name" />
                            </a-form-item>
                          </a-col>
                          <a-col :span="16">
                            <a-form-item
                              :label="$t('log.config.promtail.log_path')"
                              :field="`scrape_configs.${index}.path`"
                            >
                              <a-input
                                v-model="job.static_configs[0].labels.__path__"
                              />
                            </a-form-item>
                          </a-col>
                        </a-row>

                        <!-- Pipeline Stages (Simplified as JSON editor) -->
                        <a-form-item
                          :label="$t('log.config.promtail.pipeline')"
                          :field="`scrape_configs.${index}.pipeline`"
                        >
                          <a-textarea
                            :model-value="
                              JSON.stringify(job.pipeline_stages, null, 2)
                            "
                            :auto-size="{ minRows: 3, maxRows: 10 }"
                            style="font-family: monospace; font-size: 12px"
                            :placeholder="$t('log.config.placeholder.pipeline')"
                            @input="(val) => updatePipelineStages(index, val)"
                          />
                          <template #help>{{
                            $t('log.config.promtail.pipeline.help')
                          }}</template>
                        </a-form-item>
                      </a-card>

                      <a-button type="dashed" long @click="addScrapeJob">
                        <template #icon><icon-plus /></template>
                        {{ $t('log.config.promtail.add_job') }}
                      </a-button>
                    </a-space>
                  </a-collapse-item>

                  <!-- Positions -->
                  <a-collapse-item
                    key="positions"
                    :header="$t('log.config.section.positions')"
                  >
                    <a-form-item
                      :label="$t('log.config.promtail.positions_file')"
                      field="positions.filename"
                    >
                      <a-input v-model="promtailForm.positions.filename" />
                    </a-form-item>
                  </a-collapse-item>
                </a-collapse>
              </a-form>
            </a-spin>
          </a-card>
        </a-space>
      </a-tab-pane>
    </a-tabs>
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted, computed, reactive } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    getModules,
    getModuleSwitches,
    setModuleSwitch,
    getLoggerLevels,
    setLoggerLevel,
    restartProcess,
    getConfigYaml,
    saveConfigYaml,
    LabelValue,
  } from '@/api/log';
  import { Message, Modal } from '@arco-design/web-vue';

  const { t } = useI18n();

  // --- Business Config ---
  const loadingModules = ref(false);
  const moduleList = ref<LabelValue[]>([]);
  const moduleSwitches = ref<Record<string, boolean>>({});
  const loadingLevels = ref(false);
  const levels = ref<Record<string, string>>({});
  const logLevels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'OFF'];

  const levelsData = computed(() => {
    return Object.keys(levels.value).map((key) => ({
      name: key,
      level: levels.value[key],
    }));
  });

  const fetchModules = async () => {
    loadingModules.value = true;
    try {
      const [{ data: modules }, { data: switches }] = await Promise.all([
        getModules(),
        getModuleSwitches(),
      ]);
      moduleList.value = modules;
      moduleSwitches.value = switches;
    } catch (err) {
      // ignore
    } finally {
      loadingModules.value = false;
    }
  };

  const handleToggleModule = async (mod: string, enabled: boolean) => {
    try {
      await setModuleSwitch(mod, enabled);
      const module = moduleList.value.find((m) => m.value === mod);
      Message.success(
        t('log.config.message.module.success', {
          mod: module ? module.label : mod,
          status: enabled
            ? t('log.config.switch.on')
            : t('log.config.switch.off'),
        })
      );
      // Refresh only switches
      const { data } = await getModuleSwitches();
      moduleSwitches.value = data;
    } catch (err) {
      Message.error(t('log.config.message.fail'));
    }
  };

  const fetchLevels = async () => {
    loadingLevels.value = true;
    try {
      const { data } = await getLoggerLevels();
      levels.value = data;
    } catch (err) {
      // ignore
    } finally {
      loadingLevels.value = false;
    }
  };

  const handleChangeLevel = async (name: string, level: string) => {
    try {
      await setLoggerLevel(name, level);
      Message.success(t('log.config.message.level.success', { name, level }));
      fetchLevels();
    } catch (err) {
      Message.error(t('log.config.message.fail'));
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'DEBUG':
        return 'gray';
      case 'INFO':
        return 'green';
      case 'WARN':
        return 'orange';
      case 'ERROR':
        return 'red';
      default:
        return 'gray';
    }
  };

  // --- Advanced Config ---
  const loadingLoki = ref(false);
  const savingLoki = ref(false);

  // Define Loki Form Structure
  const lokiForm = reactive({
    auth_enabled: false,
    server: {
      http_listen_port: 3100,
      grpc_listen_port: 9096,
    },
    common: {
      instance_addr: '127.0.0.1',
      path_prefix: './loki-data',
      replication_factor: 1,
      storage: {
        filesystem: {
          chunks_directory: './loki-data/chunks',
          rules_directory: './loki-data/rules',
        },
      },
    },
    limits_config: {
      max_entries_limit_per_query: 5000,
      retention_period: '168h',
    },
    compactor: {
      working_directory: '/tmp/loki/boltdb-shipper-compactor',
      compaction_interval: '10m',
      retention_enabled: true,
    },
    // Keep other fields
    schema_config: {},
    ruler: {},
  });

  const loadingPromtail = ref(false);
  const savingPromtail = ref(false);

  // Define Promtail Form Structure
  const promtailForm = reactive({
    server: {
      http_listen_port: 9080,
      grpc_listen_port: 0,
    },
    positions: {
      filename: './config/promtail-positions.yaml',
    },
    clients: [{ url: 'http://127.0.0.1:3100/loki/api/v1/push' }],
    scrape_configs: [] as any[],
  });

  const fetchLokiConfig = async () => {
    loadingLoki.value = true;
    try {
      const { data } = await getConfigYaml('loki-config.yaml');

      // Merge data into lokiForm
      if (data) {
        lokiForm.auth_enabled = data.auth_enabled || false;
        if (data.server) Object.assign(lokiForm.server, data.server);
        if (data.common) {
          // Deep merge for storage
          if (data.common.storage && data.common.storage.filesystem) {
            lokiForm.common.storage.filesystem = data.common.storage.filesystem;
          }
          // Merge other common fields
          lokiForm.common.instance_addr =
            data.common.instance_addr || lokiForm.common.instance_addr;
          lokiForm.common.path_prefix =
            data.common.path_prefix || lokiForm.common.path_prefix;
        }

        if (data.limits_config)
          Object.assign(lokiForm.limits_config, data.limits_config);
        if (data.compactor) Object.assign(lokiForm.compactor, data.compactor);

        // Preserve others
        lokiForm.schema_config = data.schema_config || {};
        lokiForm.ruler = data.ruler || {};
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
    } finally {
      loadingLoki.value = false;
    }
  };

  const confirmRestart = () => {
    Modal.confirm({
      title: t('log.config.restart.title'),
      content: t('log.config.restart.content'),
      onOk: async () => {
        try {
          await restartProcess();
          Message.success(t('log.config.message.restart.success'));
        } catch (err) {
          Message.error(t('log.config.message.fail'));
        }
      },
    });
  };

  const saveLokiConfig = async () => {
    savingLoki.value = true;
    try {
      // Construct the config object
      // We use the reactive form directly as it mirrors the structure
      // But we need to ensure common.storage structure is correct
      const config = JSON.parse(JSON.stringify(lokiForm));

      await saveConfigYaml('loki-config.yaml', config);
      confirmRestart();
    } catch (err) {
      Message.error(t('log.config.message.fail'));
    } finally {
      savingLoki.value = false;
    }
  };

  const fetchPromtailConfig = async () => {
    loadingPromtail.value = true;
    try {
      const { data } = await getConfigYaml('promtail-config.yaml');

      if (data) {
        if (data.server) Object.assign(promtailForm.server, data.server);
        if (data.positions)
          Object.assign(promtailForm.positions, data.positions);
        if (data.clients) promtailForm.clients = data.clients;
        if (data.scrape_configs) {
          promtailForm.scrape_configs = data.scrape_configs.map((job: any) => {
            // Ensure structure exists
            if (!job.static_configs)
              job.static_configs = [
                { targets: ['localhost'], labels: { __path__: '' } },
              ];
            if (!job.static_configs[0].labels)
              job.static_configs[0].labels = { __path__: '' };
            return job;
          });
        }
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
    } finally {
      loadingPromtail.value = false;
    }
  };

  const updatePipelineStages = (index: number, val: string) => {
    try {
      const parsed = JSON.parse(val);
      promtailForm.scrape_configs[index].pipeline_stages = parsed;
    } catch (e) {
      // ignore parse error while typing
    }
  };

  const addScrapeJob = () => {
    promtailForm.scrape_configs.push({
      job_name: t('log.config.job.new_job_name'),
      static_configs: [
        {
          targets: ['localhost'],
          labels: {
            job: t('log.config.job.new_job_name'),
            __path__: t('log.config.job.new_job_path'),
          },
        },
      ],
      pipeline_stages: [],
    });
  };

  const removeScrapeJob = (index: number) => {
    promtailForm.scrape_configs.splice(index, 1);
  };

  const savePromtailConfig = async () => {
    savingPromtail.value = true;
    try {
      const config = JSON.parse(JSON.stringify(promtailForm));
      await saveConfigYaml('promtail-config.yaml', config);
      confirmRestart();
    } catch (err) {
      Message.error(t('log.config.message.fail'));
    } finally {
      savingPromtail.value = false;
    }
  };

  onMounted(() => {
    fetchModules();
    fetchLevels();
    fetchLokiConfig();
    fetchPromtailConfig();
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
  }
  .module-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 15px;
    border: 1px solid var(--color-neutral-3);
    border-radius: 4px;
    background-color: var(--color-bg-2);
  }
  .module-name {
    font-weight: 500;
  }
  .empty-tip {
    color: var(--color-text-3);
    padding: 20px;
  }
  .job-card {
    border: 1px solid var(--color-neutral-3);
    margin-bottom: 10px;
  }
</style>
