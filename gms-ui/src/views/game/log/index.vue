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
              <a-col :span="8">
                <a-form-item
                  field="ip"
                  :label="$t('log.manager.form.ip.label')"
                >
                  <a-select
                    v-model="formModel.ip"
                    :placeholder="$t('log.manager.form.ip.placeholder')"
                    allow-clear
                    :options="ipOptions"
                    allow-search
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item
                  field="mac"
                  :label="$t('log.manager.form.mac.label')"
                >
                  <a-select
                    v-model="formModel.mac"
                    :placeholder="$t('log.manager.form.mac.placeholder')"
                    allow-clear
                    :options="macOptions"
                    allow-search
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="hwid"
                  :label="$t('log.manager.form.hwid.label')"
                >
                  <a-select
                    v-model="formModel.hwid"
                    :placeholder="$t('log.manager.form.hwid.placeholder')"
                    allow-clear
                    :options="hwidOptions"
                    allow-search
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="account"
                  :label="$t('log.manager.form.account.label')"
                >
                  <a-select
                    v-model="formModel.account"
                    :placeholder="$t('log.manager.form.account.placeholder')"
                    allow-clear
                    :options="accountOptions"
                    allow-search
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item
                  field="character"
                  :label="$t('log.manager.form.character.label')"
                >
                  <a-input
                    v-model="formModel.character"
                    :placeholder="$t('log.manager.form.character.placeholder')"
                    allow-clear
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
  import { ref, reactive, onMounted, watch } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    queryLogs,
    getAllMajorCategories,
    getMinorCategoriesByMajor,
    getUniqueIPs,
    getUniqueMACs,
    getUniqueHWIDs,
    getUniqueAccounts,
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

  // 筛选选项
  const ipOptions = ref<SelectOptionData[]>([]);
  const macOptions = ref<SelectOptionData[]>([]);
  const hwidOptions = ref<SelectOptionData[]>([]);
  const accountOptions = ref<SelectOptionData[]>([]);

  const formModel = reactive({
    majorCategory: '',
    minorCategory: '',
    startDate: '',
    endDate: '',
    keyword: '',
    ip: '',
    mac: '',
    hwid: '',
    account: '',
    character: '',
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

  // 监听大类和小类变化，获取对应的筛选选项
  watch(
    [() => formModel.majorCategory, () => formModel.minorCategory],
    async ([newMajor, newMinor], [oldMajor, oldMinor]) => {
      if (
        newMajor &&
        newMinor &&
        (newMajor !== oldMajor || newMinor !== oldMinor)
      ) {
        await fetchUniqueValues();
      }
    }
  );

  const fetchLogs = async () => {
    if (!formModel.majorCategory || !formModel.minorCategory) {
      Message.warning(t('log.manager.message.selectCategoryFirst'));
      return;
    }

    try {
      setLoading(true);
      const params: LogQueryParams = {
        majorCategory: formModel.majorCategory || undefined,
        minorCategory: formModel.minorCategory || undefined,
        startDate: formModel.startDate || undefined,
        endDate: formModel.endDate || undefined,
        keyword: formModel.keyword || undefined,
        ip: formModel.ip || undefined,
        mac: formModel.mac || undefined,
        hwid: formModel.hwid || undefined,
        account: formModel.account || undefined,
        character: formModel.character || undefined,
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

  // 获取唯一值（IP、MAC、HWID、账号等）
  const fetchUniqueValues = async () => {
    if (!formModel.majorCategory || !formModel.minorCategory) return;

    try {
      // 获取唯一IP列表
      const ipResponse = (await getUniqueIPs(
        formModel.majorCategory,
        formModel.minorCategory
      )) as unknown as HttpResponse<{ data: string[] }>;
      ipOptions.value = (ipResponse.data?.data || []).map((ip) => ({
        label: ip,
        value: ip,
      }));

      // 获取唯一MAC列表
      const macResponse = (await getUniqueMACs(
        formModel.majorCategory,
        formModel.minorCategory
      )) as unknown as HttpResponse<{ data: string[] }>;
      macOptions.value = (macResponse.data?.data || []).map((mac) => ({
        label: mac,
        value: mac,
      }));

      // 获取唯一HWID列表
      const hwidResponse = (await getUniqueHWIDs(
        formModel.majorCategory,
        formModel.minorCategory
      )) as unknown as HttpResponse<{ data: string[] }>;
      hwidOptions.value = (hwidResponse.data?.data || []).map((hwid) => ({
        label: hwid,
        value: hwid,
      }));

      // 获取唯一账号列表
      const accountResponse = (await getUniqueAccounts(
        formModel.majorCategory,
        formModel.minorCategory
      )) as unknown as HttpResponse<{ data: string[] }>;
      accountOptions.value = (accountResponse.data?.data || []).map(
        (account) => ({
          label: account,
          value: account,
        })
      );
    } catch (error) {
      Message.error(t('log.manager.message.fetchUniqueValuesError'));
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
    formModel.ip = '';
    formModel.mac = '';
    formModel.hwid = '';
    formModel.account = '';
    formModel.character = '';

    // 清空选项
    ipOptions.value = [];
    macOptions.value = [];
    hwidOptions.value = [];
    accountOptions.value = [];

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
