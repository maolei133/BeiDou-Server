<template>
  <div class="log-manager-container">
    <Breadcrumb
      :items="[
        $t('log.manager.breadcrumb.game'),
        $t('log.manager.breadcrumb.log'),
      ]"
    />
    <a-card class="general-card">
      <a-row>
        <a-col :flex="'86px'" class="left-col">
          <a-button type="primary" @click="fetchLogs">
            <template #icon>
              <icon-search />
            </template>
            {{ $t('log.manager.query.button') }}
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
                <a-form-item
                  field="majorCategory"
                  :label="$t('log.manager.form.majorCategory.label')"
                >
                  <a-select
                    v-model="formModel.majorCategory"
                    :placeholder="
                      $t('log.manager.form.majorCategory.placeholder')
                    "
                    allow-clear
                    @change="handleMajorCategoryChange as any"
                  >
                    <a-option
                      v-for="item in majorCategories"
                      :key="item"
                      :value="item"
                    >
                      {{ getMajorCategoryLabel(item) }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="minorCategory"
                  :label="$t('log.manager.form.minorCategory.label')"
                >
                  <a-select
                    v-model="formModel.minorCategory"
                    :placeholder="
                      $t('log.manager.form.minorCategory.placeholder')
                    "
                    :fallback-option="getMinorCategoryFallbackOption"
                    allow-clear
                    :disabled="!formModel.majorCategory"
                  >
                    <a-option
                      v-for="item in minorCategories"
                      :key="item"
                      :value="item"
                    >
                      {{ getMinorCategoryLabel(formModel.majorCategory, item) }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="keyword"
                  :label="$t('log.manager.form.keyword.label')"
                >
                  <a-input
                    v-model="formModel.keyword"
                    :placeholder="$t('log.manager.form.keyword.placeholder')"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item
                  field="startDate"
                  :label="$t('log.manager.form.startDate.label')"
                >
                  <a-date-picker
                    v-model="formModel.startDate"
                    style="width: 100%"
                    :placeholder="$t('log.manager.form.startDate.placeholder')"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="endDate"
                  :label="$t('log.manager.form.endDate.label')"
                >
                  <a-date-picker
                    v-model="formModel.endDate"
                    style="width: 100%"
                    :placeholder="$t('log.manager.form.endDate.placeholder')"
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
          <a-table-column
            :title="$t('log.manager.table.column.content')"
            :width="300"
          >
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
  import { useI18n } from 'vue-i18n';
  import {
    queryLogs,
    getAllMajorCategories,
    getMinorCategoriesByMajor,
    LogQueryParams,
  } from '@/api/log';
  import useLoading from '@/hooks/loading';
  import { Message } from '@arco-design/web-vue';
  import type { HttpResponse } from '@/api/interceptor';
  import type { SelectOptionData } from '@arco-design/web-vue/es/select/interface';

  const { t } = useI18n();
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
      Message.error(t('log.manager.message.fetchError'));
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
      Message.error(t('log.manager.message.fetchMajorCategoriesError'));
    }
  };

  const fetchMinorCategories = async (majorCategory: string) => {
    try {
      const response = (await getMinorCategoriesByMajor(
        majorCategory
      )) as unknown as HttpResponse<string[]>;
      minorCategories.value = response.data || [];
    } catch (error) {
      Message.error(t('log.manager.message.fetchMinorCategoriesError'));
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

  // 获取大类显示标签
  const getMajorCategoryLabel = (category: string) => {
    const key = `log.category.major.${category.toLowerCase()}`;
    const translated = t(key);
    return translated !== key ? translated : category;
  };

  // 获取小类显示标签
  const getMinorCategoryLabel = (majorCategory: string, category: string) => {
    const key = `log.category.minor.${majorCategory.toLowerCase()}.${category.toLowerCase()}`;
    const translated = t(key);
    return translated !== key ? translated : category;
  };

  // 获取小类回退选项（用于显示已选择的值）
  const getMinorCategoryFallbackOption = (
    key: string | number | boolean | Record<string, unknown>
  ): SelectOptionData => {
    const keyValue = key as string;
    return {
      value: keyValue,
      label: getMinorCategoryLabel(formModel.majorCategory, keyValue),
    };
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
