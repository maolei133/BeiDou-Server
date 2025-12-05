<template>
  <div class="log-config-container">
    <el-tabs v-model="activeTab" class="config-tabs">
      <!-- 绯荤粺閰嶇疆鏍囩椤?-->
      <el-tab-pane :label="$t('logs.config.system.title')" name="system">
        <div class="config-section">
          <h3>{{ $t('logs.config.system.title') }}</h3>
          <el-form :model="systemConfig" label-width="150px">
            <el-form-item :label="$t('logs.config.system.enabled')">
              <el-switch v-model="systemConfig.enabled" />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.retentionDays')">
              <el-input-number
                v-model="systemConfig.retentionDays"
                :min="1"
                :max="365"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.fileSizeMB')">
              <el-input-number
                v-model="systemConfig.fileSizeMB"
                :min="10"
                :max="1000"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.compressionEnabled')">
              <el-switch v-model="systemConfig.compressionEnabled" />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.compressionFormat')">
              <el-select v-model="systemConfig.compressionFormat">
                <el-option label="GZIP" value="GZIP" />
                <el-option label="ZIP" value="ZIP" />
                <el-option label="DEFLATE" value="DEFLATE" />
              </el-select>
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.asyncThreadPoolSize')">
              <el-input-number
                v-model="systemConfig.asyncThreadPoolSize"
                :min="1"
                :max="32"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.logDir')">
              <el-input v-model="systemConfig.logDir" placeholder="/logs" />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.coldDataDays')">
              <el-input-number
                v-model="systemConfig.coldDataDays"
                :min="1"
                :max="365"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.system.warmDataDays')">
              <el-input-number
                v-model="systemConfig.warmDataDays"
                :min="1"
                :max="365"
              />
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveSystemConfig">
                {{ $t('logs.config.system.save') }}
              </el-button>
              <el-button @click="loadSystemConfig">
                {{ $t('logs.config.system.reload') }}
              </el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <!-- 鎬ц兘閰嶇疆鏍囩椤?-->
      <el-tab-pane
        :label="$t('logs.config.performance.title')"
        name="performance"
      >
        <div class="config-section">
          <h3>{{ $t('logs.config.performance.title') }}</h3>

          <div class="performance-level">
            <h4>{{ $t('logs.config.performance.high') }}</h4>
            <el-form :model="performanceConfig.HIGH" label-width="120px">
              <el-form-item :label="$t('logs.config.performance.bufferSize')">
                <el-input-number
                  v-model="performanceConfig.HIGH.bufferSize"
                  :min="256"
                  :max="65536"
                />
              </el-form-item>

              <el-form-item
                :label="$t('logs.config.performance.flushInterval')"
              >
                <el-input-number
                  v-model="performanceConfig.HIGH.flushInterval"
                  :min="100"
                  :max="10000"
                />
              </el-form-item>

              <el-form-item>
                <el-button
                  type="primary"
                  @click="updatePerformanceConfig('HIGH')"
                >
                  {{ $t('logs.config.system.save') }}
                </el-button>
              </el-form-item>
            </el-form>
          </div>

          <el-divider />

          <div class="performance-level">
            <h4>{{ $t('logs.config.performance.medium') }}</h4>
            <el-form :model="performanceConfig.MEDIUM" label-width="120px">
              <el-form-item :label="$t('logs.config.performance.bufferSize')">
                <el-input-number
                  v-model="performanceConfig.MEDIUM.bufferSize"
                  :min="256"
                  :max="65536"
                />
              </el-form-item>

              <el-form-item
                :label="$t('logs.config.performance.flushInterval')"
              >
                <el-input-number
                  v-model="performanceConfig.MEDIUM.flushInterval"
                  :min="100"
                  :max="10000"
                />
              </el-form-item>

              <el-form-item>
                <el-button
                  type="primary"
                  @click="updatePerformanceConfig('MEDIUM')"
                >
                  {{ $t('logs.config.system.save') }}
                </el-button>
              </el-form-item>
            </el-form>
          </div>

          <el-divider />

          <div class="performance-level">
            <h4>{{ $t('logs.config.performance.low') }}</h4>
            <el-form :model="performanceConfig.LOW" label-width="120px">
              <el-form-item :label="$t('logs.config.performance.bufferSize')">
                <el-input-number
                  v-model="performanceConfig.LOW.bufferSize"
                  :min="256"
                  :max="65536"
                />
              </el-form-item>

              <el-form-item
                :label="$t('logs.config.performance.flushInterval')"
              >
                <el-input-number
                  v-model="performanceConfig.LOW.flushInterval"
                  :min="100"
                  :max="10000"
                />
              </el-form-item>

              <el-form-item>
                <el-button
                  type="primary"
                  @click="updatePerformanceConfig('LOW')"
                >
                  {{ $t('logs.config.system.save') }}
                </el-button>
              </el-form-item>
            </el-form>
          </div>
        </div>
      </el-tab-pane>

      <!-- 鍒嗙被閰嶇疆鏍囩椤?-->
      <el-tab-pane :label="$t('logs.config.category.title')" name="category">
        <div class="config-section">
          <h3>{{ $t('logs.config.category.title') }}</h3>

          <div class="search-box">
            <el-input
              v-model="categorySearch"
              :placeholder="$t('logs.config.category.search')"
              clearable
              style="width: 300px"
            />
          </div>

          <el-table
            :data="filteredCategories"
            style="width: 100%; margin-top: 20px"
            stripe
            max-height="600"
          >
            <el-table-column
              prop="majorCategory"
              :label="$t('logs.config.category.major')"
              width="100"
            />
            <el-table-column
              prop="minorCategory"
              :label="$t('logs.config.category.minor')"
              width="100"
            />
            <el-table-column
              prop="description"
              :label="$t('logs.config.category.description')"
              min-width="150"
            />
            <el-table-column
              prop="level"
              :label="$t('logs.config.category.level')"
              width="100"
            >
              <template #default="scope">
                <el-tag
                  :type="
                    scope && scope.row ? getLevelType(scope.row.level) : 'info'
                  "
                  >{{ scope && scope.row ? scope.row.level : '' }}</el-tag
                >
              </template>
            </el-table-column>
            <el-table-column
              prop="enabled"
              :label="$t('logs.config.category.enabled')"
              width="60"
            >
              <template #default="scope">
                <el-switch
                  :model-value="scope && scope.row && scope.row.enabled"
                  @update:model-value="
                    (val) => {
                      if (scope && scope.row) {
                        scope.row.enabled = val;
                        updateCategoryConfig(scope.row);
                      }
                    }
                  "
                />
              </template>
            </el-table-column>
            <el-table-column
              prop="consoleOutput"
              :label="$t('logs.config.category.consoleOutput')"
              width="100"
            >
              <template #default="scope">
                <el-switch
                  :model-value="scope && scope.row && scope.row.consoleOutput"
                  @update:model-value="
                    (val) => {
                      if (scope && scope.row) {
                        scope.row.consoleOutput = val;
                        updateCategoryConfig(scope.row);
                      }
                    }
                  "
                />
              </template>
            </el-table-column>
            <el-table-column
              prop="fileOutput"
              :label="$t('logs.config.category.fileOutput')"
              width="100"
            >
              <template #default="scope">
                <el-switch
                  :model-value="scope && scope.row && scope.row.fileOutput"
                  @update:model-value="
                    (val) => {
                      if (scope && scope.row) {
                        scope.row.fileOutput = val;
                        updateCategoryConfig(scope.row);
                      }
                    }
                  "
                />
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 缃戠粶鍖呴厤缃爣绛鹃〉 -->
      <el-tab-pane :label="$t('logs.config.packet.title')" name="packet">
        <div class="config-section">
          <h3>{{ $t('logs.config.packet.title') }}</h3>

          <el-form :model="packetConfig" label-width="150px">
            <el-form-item :label="$t('logs.config.packet.inPacketLogEnabled')">
              <el-switch v-model="packetConfig.inPacketLogEnabled" />
            </el-form-item>

            <el-form-item :label="$t('logs.config.packet.outPacketLogEnabled')">
              <el-switch v-model="packetConfig.outPacketLogEnabled" />
            </el-form-item>

            <el-form-item
              :label="$t('logs.config.packet.monitoredChrLogEnabled')"
            >
              <el-switch v-model="packetConfig.monitoredChrLogEnabled" />
            </el-form-item>

            <el-form-item
              :label="$t('logs.config.packet.capturePacketContent')"
            >
              <el-switch v-model="packetConfig.capturePacketContent" />
            </el-form-item>

            <el-form-item
              :label="$t('logs.config.packet.maxPacketContentLength')"
            >
              <el-input-number
                v-model="packetConfig.maxPacketContentLength"
                :min="256"
                :max="65536"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.packet.inPacketBufferSize')">
              <el-input-number
                v-model="packetConfig.inPacketBufferSize"
                :min="256"
                :max="65536"
              />
            </el-form-item>

            <el-form-item :label="$t('logs.config.packet.outPacketBufferSize')">
              <el-input-number
                v-model="packetConfig.outPacketBufferSize"
                :min="256"
                :max="65536"
              />
            </el-form-item>

            <el-form-item
              :label="$t('logs.config.packet.packetLogFlushInterval')"
            >
              <el-input-number
                v-model="packetConfig.packetLogFlushInterval"
                :min="100"
                :max="10000"
              />
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="savePacketConfig">
                {{ $t('logs.config.system.save') }}
              </el-button>
              <el-button @click="loadPacketConfig">
                {{ $t('logs.config.system.reload') }}
              </el-button>
            </el-form-item>
          </el-form>

          <el-divider />

          <h3>{{ $t('logs.config.packet.blocklist') }}</h3>

          <div class="blocklist-section">
            <h4>{{ $t('logs.config.packet.inPacketBlocklist') }}</h4>
            <el-input-number
              v-model="newInBlockOpcode"
              :min="0"
              :max="65535"
              :placeholder="$t('logs.config.packet.opcodeInput')"
              style="width: 200px"
            />
            <el-button
              type="primary"
              style="margin-left: 10px"
              @click="addInPacketBlock"
            >
              {{ $t('logs.config.packet.addBlock') }}
            </el-button>

            <div style="margin-top: 10px">
              <el-tag
                v-for="opcode in packetConfig.inPacketBlocklist"
                :key="opcode"
                closable
                @close="removeInPacketBlock(opcode)"
              >
                {{ opcode }}
              </el-tag>
            </div>
          </div>

          <el-divider />

          <div class="blocklist-section">
            <h4>{{ $t('logs.config.packet.outPacketBlocklist') }}</h4>
            <el-input-number
              v-model="newOutBlockOpcode"
              :min="0"
              :max="65535"
              :placeholder="$t('logs.config.packet.opcodeInput')"
              style="width: 200px"
            />
            <el-button
              type="primary"
              style="margin-left: 10px"
              @click="addOutPacketBlock"
            >
              {{ $t('logs.config.packet.addBlock') }}
            </el-button>

            <div style="margin-top: 10px">
              <el-tag
                v-for="opcode in packetConfig.outPacketBlocklist"
                :key="opcode"
                closable
                @close="removeOutPacketBlock(opcode)"
              >
                {{ opcode }}
              </el-tag>
            </div>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script lang="ts">
  import logsApi from '@/api/logs';

  export default {
    name: 'LogConfig',
    data() {
      return {
        activeTab: 'system',
        systemConfig: {
          enabled: true,
          retentionDays: 30,
          fileSizeMB: 100,
          compressionEnabled: true,
          compressionFormat: 'GZIP',
          asyncThreadPoolSize: 4,
          asyncQueueSize: 10000,
          logDir: '/logs',
          coldDataDays: 30,
          warmDataDays: 7,
        },
        performanceConfig: {
          HIGH: {
            bufferSize: 2048,
            flushInterval: 500,
          },
          MEDIUM: {
            bufferSize: 1024,
            flushInterval: 1000,
          },
          LOW: {
            bufferSize: 512,
            flushInterval: 5000,
          },
        },
        categories: [],
        categorySearch: '',
        packetConfig: {
          inPacketLogEnabled: true,
          outPacketLogEnabled: true,
          monitoredChrLogEnabled: true,
          inPacketBlocklist: [],
          outPacketBlocklist: [],
          monitoredCharacterIds: [],
          inPacketBufferSize: 4096,
          outPacketBufferSize: 4096,
          packetLogFlushInterval: 1000,
          capturePacketContent: false,
          maxPacketContentLength: 512,
        },
        newInBlockOpcode: null,
        newOutBlockOpcode: null,
        loading: false,
      };
    },
    computed: {
      filteredCategories() {
        if (!this.categorySearch) {
          return this.categories;
        }
        return this.categories.filter((cat) => {
          const searchStr = this.categorySearch.toLowerCase();
          return (
            cat.majorCategory.toLowerCase().includes(searchStr) ||
            cat.minorCategory.toLowerCase().includes(searchStr) ||
            cat.description.toLowerCase().includes(searchStr)
          );
        });
      },
    },
    mounted() {
      this.loadSystemConfig();
      this.loadPerformanceConfig();
      this.loadCategories();
      this.loadPacketConfig();
    },
    methods: {
      async loadSystemConfig() {
        try {
          const response = await logsApi.getSystemConfig();
          if (response.code === 20000) {
            this.systemConfig = response.data;
            this.$message.success(
              `${this.$t('logs.config.system.loadSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.system.loadFailed')}: ${msg}`
          );
        }
      },
      async saveSystemConfig() {
        try {
          const response = await logsApi.updateSystemConfig(this.systemConfig);
          if (response.code === 20000) {
            this.$message.success(
              `${this.$t('logs.config.system.saveSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.system.saveFailed')}: ${msg}`
          );
        }
      },
      async loadPerformanceConfig() {
        try {
          const response = await logsApi.getPerformanceConfig();
          if (response.code === 20000) {
            this.performanceConfig = response.data;
            this.$message.success(
              `${this.$t('logs.config.performance.loadSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.performance.loadFailed')}: ${msg}`
          );
        }
      },
      async updatePerformanceConfig(level: string) {
        try {
          const config =
            this.performanceConfig[
              level as keyof typeof this.performanceConfig
            ];
          const response = await logsApi.updatePerformanceConfig(
            level,
            config.bufferSize,
            config.flushInterval
          );
          if (response.code === 20000) {
            this.$message.success(
              `${level} ${this.$t('logs.config.performance.saveSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.performance.saveFailed')}: ${msg}`
          );
        }
      },
      async loadCategories() {
        try {
          const response = await logsApi.getAllCategoryConfig();
          if (response.code === 20000) {
            this.categories = response.data;
            this.$message.success(
              `${this.$t('logs.config.category.loadSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.category.loadFailed')}: ${msg}`
          );
        }
      },
      async updateCategoryConfig(category: any) {
        try {
          const response = await logsApi.updateCategoryConfig(
            category.majorCategory,
            category.minorCategory,
            category.enabled,
            category.consoleOutput,
            category.fileOutput
          );
          if (response.code === 20000) {
            this.$message.success(
              `${category.majorCategory}.${category.minorCategory} ${this.$t(
                'logs.config.category.updateSuccess'
              )}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.category.updateFailed')}: ${msg}`
          );
        }
      },
      getLevelType(level: string) {
        if (level === 'HIGH') return 'danger';
        if (level === 'MEDIUM') return 'warning';
        return 'info';
      },
      async loadPacketConfig() {
        try {
          const response = await logsApi.getPacketConfig();
          if (response.code === 20000) {
            this.packetConfig = response.data;
            this.$message.success(
              `${this.$t('logs.config.packet.loadSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.loadFailed')}: ${msg}`
          );
        }
      },
      async savePacketConfig() {
        try {
          const response = await logsApi.updatePacketConfig(this.packetConfig);
          if (response.code === 20000) {
            this.$message.success(
              `${this.$t('logs.config.packet.saveSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.saveFailed')}: ${msg}`
          );
        }
      },
      async addInPacketBlock() {
        if (this.newInBlockOpcode === null || this.newInBlockOpcode === '') {
          this.$message.warning(
            `${this.$t('logs.config.packet.inputOpcodeWarning')}`
          );
          return;
        }
        try {
          const response = await logsApi.addInPacketBlock(
            this.newInBlockOpcode
          );
          if (response.code === 20000) {
            this.packetConfig.inPacketBlocklist.push(this.newInBlockOpcode);
            this.newInBlockOpcode = null;
            this.$message.success(
              `${this.$t('logs.config.packet.addBlockSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.addBlockFailed')}: ${msg}`
          );
        }
      },
      async removeInPacketBlock(opcode: number) {
        try {
          const response = await logsApi.removeInPacketBlock(opcode);
          if (response.code === 20000) {
            this.packetConfig.inPacketBlocklist =
              this.packetConfig.inPacketBlocklist.filter((o) => o !== opcode);
            this.$message.success(
              `${this.$t('logs.config.packet.removeBlockSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.removeBlockFailed')}: ${msg}`
          );
        }
      },
      async addOutPacketBlock() {
        if (this.newOutBlockOpcode === null || this.newOutBlockOpcode === '') {
          this.$message.warning(
            `${this.$t('logs.config.packet.inputOpcodeWarning')}`
          );
          return;
        }
        try {
          const response = await logsApi.addOutPacketBlock(
            this.newOutBlockOpcode
          );
          if (response.code === 20000) {
            this.packetConfig.outPacketBlocklist.push(this.newOutBlockOpcode);
            this.newOutBlockOpcode = null;
            this.$message.success(
              `${this.$t('logs.config.packet.addBlockSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.addBlockFailed')}: ${msg}`
          );
        }
      },
      async removeOutPacketBlock(opcode: number) {
        try {
          const response = await logsApi.removeOutPacketBlock(opcode);
          if (response.code === 20000) {
            this.packetConfig.outPacketBlocklist =
              this.packetConfig.outPacketBlocklist.filter((o) => o !== opcode);
            this.$message.success(
              `${this.$t('logs.config.packet.removeBlockSuccess')}`
            );
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(
            `${this.$t('logs.config.packet.removeBlockFailed')}: ${msg}`
          );
        }
      },
    },
  };
</script>

<style scoped>
  .log-config-container {
    padding: 20px;
    background-color: transparent;
    min-height: auto;
  }

  .config-tabs {
    background-color: white;
    border-radius: 6px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.08);
    border: 1px solid #ebeef5;
  }

  .config-section {
    padding: 20px 25px;
    animation: fadeIn 0.3s ease;
  }

  .config-section h3 {
    margin-top: 0;
    color: #303133;
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid #f5f7fa;
  }

  .performance-level {
    background-color: #f5f7fa;
    padding: 15px;
    border-radius: 6px;
    margin-bottom: 20px;
    border-left: 4px solid #667eea;
  }

  .performance-level h4 {
    color: #303133;
    margin-top: 0;
    margin-bottom: 15px;
    font-weight: 600;
  }

  .search-box {
    margin-bottom: 20px;
  }

  .blocklist-section {
    padding: 15px;
    background-color: #f5f7fa;
    border-radius: 6px;
    margin-top: 15px;
    border: 1px dashed #dcdfe6;
  }

  .blocklist-section h4 {
    margin-top: 0;
    margin-bottom: 15px;
    color: #303133;
    font-weight: 600;
  }

  :deep(.el-form-item) {
    margin-bottom: 20px;
  }

  :deep(.el-form-item__label) {
    color: #303133;
    font-weight: 500;
  }

  :deep(.el-tag) {
    margin-right: 8px;
    margin-bottom: 8px;
    border-radius: 4px;
  }

  :deep(.el-input),
  :deep(.el-select),
  :deep(.el-input-number) {
    border-radius: 4px;
  }

  :deep(.el-button) {
    border-radius: 4px;
    font-weight: 500;
    transition: all 0.3s ease;
  }

  :deep(.el-button:hover) {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px 0 rgba(0, 0, 0, 0.15);
  }

  :deep(.el-divider) {
    margin: 20px 0;
  }

  @keyframes fadeIn {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @media (max-width: 768px) {
    .config-section {
      padding: 15px 20px;
    }

    .config-section h3 {
      font-size: 16px;
    }
  }
</style>

