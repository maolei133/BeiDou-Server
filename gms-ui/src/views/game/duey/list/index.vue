<template>
  <div class="container">
    <a-card class="general-card" title="快递列表">
      <a-row>
        <a-col :flex="1">
          <a-form
            :model="formModel"
            :label-col-props="{ span: 6 }"
            :wrapper-col-props="{ span: 18 }"
            label-align="left"
          >
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item field="receiverName" label="收件人">
                  <a-input
                    v-model="formModel.receiverName"
                    placeholder="请输入收件人"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="senderName" label="发件人">
                  <a-input
                    v-model="formModel.senderName"
                    placeholder="请输入发件人"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="timeRange" label="发送时间">
                  <a-range-picker
                    v-model="formModel.timeRange"
                    style="width: 100%"
                    show-time
                    format="YYYY-MM-DD HH:mm:ss"
                  />
                </a-form-item>
              </a-col>
              <!-- 更多筛选条件 -->
              <a-col :span="8">
                <a-form-item field="itemId" label="物品ID">
                  <a-input-number
                    v-model="formModel.itemId"
                    placeholder="请输入物品ID"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="checked" label="状态">
                  <a-select
                    v-model="formModel.checked"
                    placeholder="请选择状态"
                    allow-clear
                  >
                    <a-option :value="1">未读</a-option>
                    <a-option :value="0">已读</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="itemType" label="类型">
                  <a-select
                    v-model="formModel.itemType"
                    placeholder="请选择类型"
                    allow-clear
                  >
                    <a-option :value="0">普通</a-option>
                    <a-option :value="1">快速</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
        <a-divider style="height: 84px" direction="vertical" />
        <a-col :flex="'86px'" style="text-align: right">
          <a-space direction="vertical" :size="18">
            <a-button type="primary" @click="search">
              <template #icon>
                <icon-search />
              </template>
              查询
            </a-button>
            <a-button @click="reset">
              <template #icon>
                <icon-refresh />
              </template>
              重置
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-divider style="margin-top: 0" />
      <a-row style="margin-bottom: 16px">
        <a-col :span="12">
          <a-space>
            <a-button type="primary" @click="handleSend">
              <template #icon>
                <icon-plus />
              </template>
              发放快递
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-table
        row-key="packageId"
        :loading="loading"
        :pagination="pagination"
        :columns="columns"
        :data="renderData"
        @page-change="onPageChange"
        @page-size-change="onPageSizeChange"
      >
        <template #items="{ record }">
          <a-space wrap>
            <a-tag v-if="record.mesos > 0" color="gold">
              金币: {{ record.mesos }}
            </a-tag>
            <a-tag v-for="item in record.items" :key="item.itemId" color="blue">
              {{ item.itemId }} x {{ item.quantity }}
            </a-tag>
          </a-space>
        </template>
        <template #type="{ record }">
          <a-tag :color="record.type === 1 ? 'red' : 'green'">
            {{ record.type === 1 ? '快速' : '普通' }}
          </a-tag>
        </template>
        <template #checked="{ record }">
          <a-tag :color="record.checked === 1 ? 'orange' : 'gray'">
            {{ record.checked === 1 ? '未读' : '已读' }}
          </a-tag>
        </template>
        <template #operations="{ record }">
          <a-popconfirm
            content="确定要删除该快递吗?"
            @ok="handleDelete(record)"
          >
            <a-button type="text" status="danger" size="small"> 删除 </a-button>
          </a-popconfirm>
        </template>
      </a-table>
    </a-card>

    <SendDueyModal v-model:visible="sendVisible" @success="search" />
  </div>
</template>

<script lang="ts" setup>
  import { computed, ref, reactive, onMounted } from 'vue';
  import useLoading from '@/hooks/loading';
  import { Pagination } from '@/types/global';
  import {
    getDueyList,
    deleteDueyPackage,
    DueyPackage,
    DueyListParams,
  } from '@/api/duey';
  import { Message, TableColumnData } from '@arco-design/web-vue';
  import {
    IconSearch,
    IconRefresh,
    IconPlus,
  } from '@arco-design/web-vue/es/icon';
  import SendDueyModal from './components/SendDueyModal.vue';

  const { loading, setLoading } = useLoading(true);

  const renderData = ref<DueyPackage[]>([]);
  const formModel = reactive({
    receiverName: '',
    senderName: '',
    timeRange: [],
    itemId: undefined,
    checked: undefined,
    itemType: undefined,
  });

  const basePagination: Pagination = {
    current: 1,
    pageSize: 20,
  };
  const pagination = reactive({
    ...basePagination,
  });

  const sendVisible = ref(false);

  const columns = computed<TableColumnData[]>(() => [
    {
      title: '包裹ID',
      dataIndex: 'packageId',
      width: 100,
    },
    {
      title: '收件人',
      dataIndex: 'receiverName',
      width: 120,
    },
    {
      title: '发件人',
      dataIndex: 'senderName',
      width: 120,
    },
    {
      title: '物品/金币',
      slotName: 'items',
    },
    {
      title: '留言',
      dataIndex: 'message',
      ellipsis: true,
      tooltip: true,
    },
    {
      title: '类型',
      slotName: 'type',
      width: 80,
    },
    {
      title: '状态',
      slotName: 'checked',
      width: 80,
    },
    {
      title: '发送时间',
      dataIndex: 'timestamp',
      width: 180,
    },
    {
      title: '操作',
      slotName: 'operations',
      width: 100,
      fixed: 'right',
    },
  ]);

  const fetchData = async (
    params: DueyListParams = { pageNo: 1, pageSize: 20 }
  ) => {
    setLoading(true);
    try {
      const { data } = await getDueyList(params);
      renderData.value = data.records;
      pagination.current = params.pageNo;
      pagination.total = data.totalRow;
    } catch (err) {
      // err
    } finally {
      setLoading(false);
    }
  };

  const search = () => {
    const params: DueyListParams = {
      pageNo: 1,
      pageSize: pagination.pageSize,
      ...formModel,
    } as unknown as DueyListParams;

    if (formModel.timeRange && formModel.timeRange.length === 2) {
      params.startTime = new Date(formModel.timeRange[0]).getTime();
      params.endTime = new Date(formModel.timeRange[1]).getTime();
    }

    fetchData(params);
  };

  const onPageChange = (current: number) => {
    fetchData({ ...basePagination, pageNo: current });
  };

  const onPageSizeChange = (pageSize: number) => {
    basePagination.pageSize = pageSize;
    fetchData({ ...basePagination, pageNo: 1 });
  };

  const reset = () => {
    formModel.receiverName = '';
    formModel.senderName = '';
    formModel.timeRange = [];
    formModel.itemId = undefined;
    formModel.checked = undefined;
    formModel.itemType = undefined;
    search();
  };

  const handleSend = () => {
    sendVisible.value = true;
  };

  const handleDelete = async (record: DueyPackage) => {
    try {
      await deleteDueyPackage(record.packageId);
      Message.success('删除成功');
      search();
    } catch (err) {
      // err
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
  :deep(.arco-table-th) {
    &:last-child {
      .arco-table-th-item-title {
        margin-left: 16px;
      }
    }
  }
  .action-icon {
    margin-left: 12px;
    cursor: pointer;
  }
  .active {
    color: #0960bd;
    background-color: #e3f4fc;
  }
  .setting {
    display: flex;
    align-items: center;
    width: 200px;
    .title {
      margin-left: 12px;
      cursor: pointer;
    }
  }

  /* 移动端适配 */
  @media (max-width: 768px) {
    .arco-form-item {
      margin-bottom: 16px;
    }
    .arco-col-8 {
      width: 100% !important;
      flex: 0 0 100% !important;
      max-width: 100% !important;
    }
    .arco-divider-vertical {
      display: none;
    }
    .arco-col-flex-86px {
      text-align: left !important;
      margin-top: 10px;
      width: 100%;
      flex: 0 0 100% !important;
    }
  }
</style>
