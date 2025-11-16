<template>
  <div class="log-manager-container">
    <Breadcrumb :items="['游戏管理', '日志管理']" />
    <a-card class="general-card">
      <a-row>
        <a-col :flex="'86px'" class="left-col">
          <a-button type="primary" @click="fetchLogs">
            <template #icon>
              <icon-search />
            </template>
            查询
          </a-button>
        </a-col>
      </a-row>
      <a-row>
        <a-col :span="24">
          <a-form
            :model="formModel"
            :label-col-props="{ span: 6 }"
            :wrapper-col-props="{ span: 18 }"
            label-align="left"
            auto-label-width
          >
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item field="majorCategory" label="日志大类">
                  <a-select
                    v-model="formModel.majorCategory"
                    placeholder="请选择日志大类"
                    allow-clear
                    @change="handleMajorCategoryChange as any"
                  >
                    <a-option
                      v-for="item in majorCategories"
                      :key="item"
                      :value="item"
                    >
                      {{ item }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="minorCategory" label="日志小类">
                  <a-select
                    v-model="formModel.minorCategory"
                    placeholder="请选择日志小类"
                    allow-clear
                    :disabled="!formModel.majorCategory"
                  >
                    <a-option
                      v-for="item in minorCategories"
                      :key="item"
                      :value="item"
                    >
                      {{ item }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="keyword" label="关键词">
                  <a-input
                    v-model="formModel.keyword"
                    placeholder="请输入关键词"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item field="startDate" label="开始日期">
                  <a-date-picker
                    v-model="formModel.startDate"
                    style="width: 100%"
                    placeholder="请选择开始日期"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="endDate" label="结束日期">
                  <a-date-picker
                    v-model="formModel.endDate"
                    style="width: 100%"
                    placeholder="请选择结束日期"
                  />
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
      </a-row>
    </a-card>
    <a-card class="general-card" style="margin-top: 16px">
      <a-table
        :data="logData as any"
        :loading="loading"
        :pagination="pagination"
        column-resizable
        @page-change="handlePageChange"
        @page-size-change="handlePageSizeChange"
      >
        <template #columns>
          <a-table-column title="日志内容" :width="300">
            <template #cell="{ record }">
              <div class="log-content">{{ record }}</div>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, reactive, onMounted } from 'vue';
  import {
    queryLogs,
    getAllMajorCategories,
    getMinorCategoriesByMajor,
    LogQueryParams,
  } from '@/api/log';
  import useLoading from '@/hooks/loading';
  import { Message } from '@arco-design/web-vue';
  import type { HttpResponse } from '@/api/interceptor';

  const { loading, setLoading } = useLoading(true);
  const logData = ref<string[]>([]);
  const majorCategories = ref<string[]>([]);
  const minorCategories = ref<string[]>([]);

  const formModel = reactive({
    majorCategory: '',
    minorCategory: '',
    startDate: '',
    endDate: '',
    keyword: '',
  });

  const pagination = reactive({
    current: 1,
    pageSize: 20,
    total: 0,
    showPageSize: true,
    showTotal: true,
    pageSizeOptions: [10, 20, 30, 50],
  });

  onMounted(() => {
    fetchMajorCategories();
  });

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const params: LogQueryParams = {
        majorCategory: formModel.majorCategory || undefined,
        minorCategory: formModel.minorCategory || undefined,
        startDate: formModel.startDate || undefined,
        endDate: formModel.endDate || undefined,
        keyword: formModel.keyword || undefined,
      };

      const response = (await queryLogs(params)) as unknown as HttpResponse<
        string[]
      >;
      logData.value = response.data || [];
      pagination.total = logData.value.length;
    } catch (error) {
      Message.error('查询日志时发生错误');
    } finally {
      setLoading(false);
    }
  };

  const fetchMajorCategories = async () => {
    try {
      const response =
        (await getAllMajorCategories()) as unknown as HttpResponse<string[]>;
      majorCategories.value = response.data || [];
    } catch (error) {
      Message.error('获取大类列表时发生错误');
    }
  };

  const fetchMinorCategories = async (majorCategory: string) => {
    try {
      const response = (await getMinorCategoriesByMajor(
        majorCategory
      )) as unknown as HttpResponse<string[]>;
      minorCategories.value = response.data || [];
    } catch (error) {
      Message.error('获取小类列表时发生错误');
      minorCategories.value = [];
    }
  };

  const handleMajorCategoryChange = (
    value:
      | string
      | number
      | boolean
      | Record<string, any>
      | (string | number | boolean | Record<string, any>)[]
  ) => {
    // 类型转换为 string
    const stringValue = value as string;
    formModel.minorCategory = '';
    if (stringValue) {
      fetchMinorCategories(stringValue);
    } else {
      minorCategories.value = [];
    }
  };

  const handlePageChange = (current: number) => {
    pagination.current = current;
  };

  const handlePageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
  };
</script>

<script lang="ts">
  export default {
    name: 'LogManager',
  };
</script>

<style scoped lang="less">
  .log-manager-container {
    padding: 16px;

    .left-col {
      display: flex;
      align-items: center;
      margin-bottom: 16px;
    }

    .log-content {
      white-space: pre-wrap;
      word-break: break-all;
      font-family: monospace;
      font-size: 12px;
    }
  }
</style>
