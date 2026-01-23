<template>
  <div class="monster-book-tab">
    <a-space class="mb-16">
      <a-button type="primary" @click="handleAdd">
        <template #icon><icon-plus /></template>
        {{ $t('account.monsterbook.batchAdd') }}
      </a-button>
      <a-popconfirm
        :content="$t('account.monsterbook.delete.confirm')"
        @ok="handleBatchDelete"
      >
        <a-button
          type="primary"
          status="danger"
          :disabled="!selectedKeys.length"
        >
          <template #icon><icon-delete /></template>
          {{ $t('account.monsterbook.batchDelete') }}
        </a-button>
      </a-popconfirm>
      <a-button
        type="outline"
        :disabled="!selectedKeys.length"
        @click="handleBatchUpdate"
      >
        <template #icon><icon-edit /></template>
        {{ $t('account.monsterbook.batchUpdate') }}
      </a-button>
      <a-button
        type="outline"
        :disabled="!selectedKeys.length"
        @click="handleTransfer"
      >
        <template #icon><icon-swap /></template>
        {{ $t('account.monsterbook.transfer') }}
      </a-button>
    </a-space>

    <a-table
      v-model:selectedKeys="selectedKeys"
      row-key="cardid"
      :loading="loading"
      :data="data"
      :pagination="pagination"
      :row-selection="rowSelection"
      @page-change="onPageChange"
      @page-size-change="onPageSizeChange"
    >
      <template #columns>
        <a-table-column
          :title="$t('account.monsterbook.cardid')"
          data-index="cardid"
        />
        <a-table-column
          :title="$t('account.monsterbook.cardName')"
          data-index="cardName"
        />
        <a-table-column
          :title="$t('account.monsterbook.level')"
          data-index="level"
        />
      </template>
    </a-table>

    <!-- Add Modal -->
    <a-modal
      v-model:visible="addVisible"
      :title="$t('account.monsterbook.batchAdd')"
      width="800px"
      @ok="submitAdd"
    >
      <a-tabs default-active-key="1">
        <!-- 模式1：多选新增 -->
        <a-tab-pane key="1" :title="$t('account.monsterbook.add.mode.select')">
          <a-form :model="addForm" layout="vertical">
            <a-form-item
              field="cardids"
              :label="$t('account.monsterbook.cardid')"
            >
              <a-select
                v-model="addForm.cardids"
                :loading="loadingCards"
                :placeholder="$t('account.monsterbook.search.placeholder')"
                allow-search
                multiple
                :filter-option="false"
                @search="handleSearchCards"
                @popup-visible-change="handlePopupVisibleChange"
                @dropdown-scroll="handlePopupScroll"
              >
                <a-option
                  v-for="item in cardOptions"
                  :key="item.id"
                  :value="item.id"
                  :label="`${item.name} (${item.id})`"
                />
                <template #footer>
                  <div
                    v-if="loadingCards"
                    style="text-align: center; padding: 10px 0"
                  >
                    <a-spin />
                  </div>
                </template>
              </a-select>
            </a-form-item>
            <a-form-item field="level" :label="$t('account.monsterbook.level')">
              <a-input-number v-model="addForm.level" :min="1" :max="5" />
            </a-form-item>
          </a-form>
        </a-tab-pane>

        <!-- 模式2：区间新增 -->
        <a-tab-pane key="2" :title="$t('account.monsterbook.add.mode.range')">
          <a-form :model="rangeForm" layout="vertical">
            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item
                  field="startId"
                  :label="$t('account.monsterbook.add.range.start')"
                >
                  <a-input-number v-model="rangeForm.startId" :min="0" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="endId"
                  :label="$t('account.monsterbook.add.range.end')"
                >
                  <a-input-number v-model="rangeForm.endId" :min="0" />
                </a-form-item>
              </a-col>
            </a-row>
            <a-form-item field="level" :label="$t('account.monsterbook.level')">
              <a-input-number v-model="rangeForm.level" :min="1" :max="5" />
            </a-form-item>
            <a-button
              type="primary"
              :loading="previewLoading"
              @click="previewRange"
            >
              {{ $t('account.monsterbook.add.preview') }}
            </a-button>
          </a-form>
        </a-tab-pane>

        <!-- 模式3：粘贴导入 -->
        <a-tab-pane key="3" :title="$t('account.monsterbook.add.mode.paste')">
          <a-form :model="pasteForm" layout="vertical">
            <a-form-item
              field="content"
              :label="$t('account.monsterbook.add.paste.label')"
            >
              <a-textarea
                v-model="pasteForm.content"
                :placeholder="$t('account.monsterbook.add.paste.placeholder')"
                :auto-size="{ minRows: 5, maxRows: 10 }"
              />
            </a-form-item>
            <a-button
              type="primary"
              :loading="previewLoading"
              @click="previewPaste"
            >
              {{ $t('account.monsterbook.add.preview') }}
            </a-button>
          </a-form>
        </a-tab-pane>
      </a-tabs>

      <!-- 预览表格 -->
      <div v-if="previewData.length > 0" class="mt-16">
        <div class="preview-title">
          {{ $t('account.monsterbook.add.preview.title') }} ({{
            previewData.length
          }})
        </div>
        <a-table
          :data="previewData"
          :pagination="{ pageSize: 5 }"
          size="small"
          :scroll="{ y: 200 }"
        >
          <template #columns>
            <a-table-column
              :title="$t('account.monsterbook.cardid')"
              data-index="cardid"
            />
            <a-table-column
              :title="$t('account.monsterbook.cardName')"
              data-index="cardName"
            />
            <a-table-column
              :title="$t('account.monsterbook.level')"
              data-index="level"
            />
          </template>
        </a-table>
      </div>
    </a-modal>

    <!-- Update Modal -->
    <a-modal
      v-model:visible="updateVisible"
      :title="$t('account.monsterbook.batchUpdate')"
      @ok="submitUpdate"
    >
      <a-form :model="updateForm">
        <a-form-item field="newLevel" :label="$t('account.monsterbook.level')">
          <a-input-number v-model="updateForm.newLevel" :min="1" :max="5" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Transfer Modal -->
    <a-modal
      v-model:visible="transferVisible"
      :title="$t('account.monsterbook.transfer')"
      @ok="submitTransfer"
    >
      <a-form :model="transferForm">
        <a-form-item
          field="newCharId"
          :label="$t('account.monsterbook.transfer.newCharId')"
        >
          <a-input-number v-model="transferForm.newCharId" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
  import { ref, reactive, watch } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import {
    getMonsterBookList,
    batchDeleteMonsterBook,
    batchAddMonsterBook,
    batchUpdateMonsterBook,
    transferMonsterBook,
    MonsterBookItem,
    MonsterBookUpdateItem,
  } from '@/api/monsterbook';
  import { informationSearch, InformationResult } from '@/api/information';
  import { Pagination } from '@/types/global';

  const props = defineProps({
    charId: {
      type: Number,
      required: true,
    },
  });

  const { t } = useI18n();
  const loading = ref(false);
  const data = ref<MonsterBookItem[]>([]);
  const selectedKeys = ref<number[]>([]);
  const pagination = reactive<Pagination>({
    current: 1,
    pageSize: 10,
    total: 0,
  });

  const rowSelection = reactive({
    type: 'checkbox' as const,
    showCheckedAll: true,
  });

  const fetchData = async () => {
    loading.value = true;
    try {
      const { data: res } = await getMonsterBookList({
        pageNo: pagination.current,
        pageSize: pagination.pageSize,
        charIds: [props.charId],
      });
      data.value = res.records;
      pagination.total = res.totalRow;
      selectedKeys.value = [];
    } catch (err) {
      // ignore
    } finally {
      loading.value = false;
    }
  };

  const onPageChange = (current: number) => {
    pagination.current = current;
    fetchData();
  };

  const onPageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    fetchData();
  };

  // Add
  const addVisible = ref(false);
  const addForm = reactive({
    cardids: [] as number[],
    level: 1,
  });
  const rangeForm = reactive({
    startId: 0,
    endId: 0,
    level: 1,
  });
  const pasteForm = reactive({
    content: '',
  });
  const previewData = ref<MonsterBookItem[]>([]);
  const loadingCards = ref(false);
  const cardOptions = ref<InformationResult[]>([]);
  const previewLoading = ref(false);

  // 分页加载相关状态
  const cardPage = ref(1);
  const cardPageSize = 20;
  const cardTotal = ref(0);
  const cardSearchKeyword = ref('');
  const hasMoreCards = ref(true);

  const loadCards = async (page: number, keyword: string, append = false) => {
    loadingCards.value = true;
    try {
      const { data: res } = await informationSearch({
        types: ['monster_card'],
        filter: keyword,
        page,
        pageSize: cardPageSize,
      });

      if (append) {
        cardOptions.value = [...cardOptions.value, ...res.records];
      } else {
        cardOptions.value = res.records;
      }

      cardTotal.value = res.totalRow;
      hasMoreCards.value = cardOptions.value.length < cardTotal.value;
    } catch (err) {
      // ignore
    } finally {
      loadingCards.value = false;
    }
  };

  const handleSearchCards = (value: string) => {
    cardSearchKeyword.value = value;
    cardPage.value = 1;
    loadCards(1, value, false);
  };

  const handlePopupVisibleChange = (visible: boolean) => {
    if (visible && cardOptions.value.length === 0) {
      handleSearchCards('');
    }
  };

  const handlePopupScroll = (e: Event) => {
    const target = e.target as HTMLElement;
    if (target.scrollTop + target.clientHeight >= target.scrollHeight - 10) {
      if (!loadingCards.value && hasMoreCards.value) {
        cardPage.value += 1;
        loadCards(cardPage.value, cardSearchKeyword.value, true);
      }
    }
  };

  const handleAdd = () => {
    addForm.cardids = [];
    addForm.level = 1;
    rangeForm.startId = 0;
    rangeForm.endId = 0;
    rangeForm.level = 1;
    pasteForm.content = '';
    previewData.value = [];
    addVisible.value = true;
    // 初始化加载第一页
    handleSearchCards('');
  };

  // 获取卡片名称
  const getCardName = async (id: number) => {
    try {
      const { data: res } = await informationSearch({
        types: ['monster_card'],
        filter: String(id),
        filterType: 1, // ID匹配
        fullMatch: true,
      });
      if (res.records.length > 0) {
        return res.records[0].name;
      }
    } catch (e) {
      // ignore
    }
    return `Card ${id}`;
  };

  const previewRange = async () => {
    if (rangeForm.startId > rangeForm.endId) {
      Message.error(t('account.monsterbook.add.range.error'));
      return;
    }
    previewLoading.value = true;
    const items: MonsterBookItem[] = [];
    const maxPreview = 100;
    let count = 0;

    try {
      for (let i = rangeForm.startId; i <= rangeForm.endId; i += 1) {
        if (count >= maxPreview) break;
        // eslint-disable-next-line no-await-in-loop
        const name = await getCardName(i);
        // 过滤掉不存在的卡片（名称为 Card {id} 的视为未找到，或者根据业务需求调整）
        // 这里假设如果后端返回了名称，则说明卡片存在。
        // 如果后端返回的是 "Unknown" 或者默认值，可能需要进一步判断。
        // 根据 CommonInformation.java 的逻辑，如果找不到 mobId，name 会是 "Unknown"。
        if (name && name !== 'Unknown' && !name.startsWith('Card ')) {
          items.push({
            charid: props.charId,
            cardid: i,
            level: rangeForm.level,
            cardName: name,
          });
        }
        count += 1;
      }
      previewData.value = items;
      if (rangeForm.endId - rangeForm.startId + 1 > maxPreview) {
        Message.warning(
          t('account.monsterbook.add.preview.limit', { max: maxPreview })
        );
      }
    } finally {
      previewLoading.value = false;
    }
  };

  const previewPaste = async () => {
    previewLoading.value = true;
    const lines = pasteForm.content.split(/\r?\n/);
    const separatorRegex = /[,，\t\s|=]+/;

    try {
      const promises = lines.map(async (line) => {
        const parts = line.trim().split(separatorRegex);
        if (parts.length >= 1) {
          const id = parseInt(parts[0], 10);
          if (!Number.isNaN(id)) {
            let level = 1;
            if (parts.length >= 2) {
              const lvl = parseInt(parts[1], 10);
              if (!Number.isNaN(lvl)) {
                level = Math.min(Math.max(lvl, 1), 5);
              }
            }
            const name = await getCardName(id);
            // 同样过滤不存在的卡片
            if (name && name !== 'Unknown' && !name.startsWith('Card ')) {
              return {
                charid: props.charId,
                cardid: id,
                level,
                cardName: name,
              } as MonsterBookItem;
            }
          }
        }
        return null;
      });

      const results = await Promise.all(promises);
      previewData.value = results.filter(
        (item): item is MonsterBookItem => item !== null
      );
    } finally {
      previewLoading.value = false;
    }
  };

  const submitAdd = async () => {
    let itemsToAdd: MonsterBookItem[] = [];

    // 优先使用预览数据
    if (previewData.value.length > 0) {
      itemsToAdd = previewData.value;
    } else if (addForm.cardids.length > 0) {
      // 多选添加
      itemsToAdd = addForm.cardids.map((id) => ({
        charid: props.charId,
        cardid: id,
        level: addForm.level,
      }));
    }

    if (itemsToAdd.length === 0) {
      Message.warning(t('account.monsterbook.add.noData'));
      return;
    }

    try {
      await batchAddMonsterBook(itemsToAdd);
      Message.success(t('message.success'));
      fetchData();
      addVisible.value = false;
    } catch (err) {
      // ignore
    }
  };

  // Delete
  const handleBatchDelete = async () => {
    const items = selectedKeys.value
      .map((key) => data.value.find((d) => d.cardid === key))
      .filter((item): item is MonsterBookItem => item !== undefined);

    if (items.length === 0) return;

    try {
      await batchDeleteMonsterBook(items);
      Message.success(t('message.success'));
      selectedKeys.value = [];
      fetchData();
    } catch (err) {
      // ignore
    }
  };

  // Update
  const updateVisible = ref(false);
  const updateForm = reactive({
    newLevel: 1,
  });
  const handleBatchUpdate = () => {
    updateForm.newLevel = 1;
    updateVisible.value = true;
  };
  const submitUpdate = async () => {
    const items: MonsterBookUpdateItem[] = selectedKeys.value
      .map((key) => {
        const item = data.value.find((d) => d.cardid === key);
        if (!item) return undefined;
        return {
          oldCharId: item.charid,
          oldCardId: item.cardid,
          newCardId: item.cardid,
          newLevel: updateForm.newLevel,
        };
      })
      .filter((item): item is MonsterBookUpdateItem => item !== undefined);

    if (items.length === 0) return;

    try {
      await batchUpdateMonsterBook(items);
      Message.success(t('message.success'));
      selectedKeys.value = [];
      fetchData();
    } catch (err) {
      // ignore
    }
  };

  // Transfer
  const transferVisible = ref(false);
  const transferForm = reactive({
    newCharId: 0,
  });
  const handleTransfer = () => {
    transferForm.newCharId = 0;
    transferVisible.value = true;
  };
  const submitTransfer = async () => {
    const items = selectedKeys.value
      .map((key) => data.value.find((d) => d.cardid === key))
      .filter((item): item is MonsterBookItem => item !== undefined);

    if (items.length === 0) return;

    try {
      await transferMonsterBook({
        items,
        newCharId: transferForm.newCharId,
      });
      Message.success(t('message.success'));
      selectedKeys.value = [];
      fetchData();
    } catch (err) {
      // ignore
    }
  };

  watch(
    () => props.charId,
    () => {
      if (props.charId) {
        fetchData();
      }
    },
    { immediate: true }
  );
</script>

<style scoped>
  .mb-16 {
    margin-bottom: 16px;
  }
  .mt-16 {
    margin-top: 16px;
  }
  .preview-title {
    font-weight: bold;
    margin-bottom: 8px;
  }
</style>
