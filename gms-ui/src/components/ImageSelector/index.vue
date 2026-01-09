<template>
  <a-modal
    :visible="visible"
    :title="title"
    width="800px"
    :fullscreen="isMobile"
    :ok-text="$t('account.player.warp.select')"
    @cancel="handleCancel"
    @ok="handleOk"
  >
    <div class="selector-container">
      <!-- 筛选区域 -->
      <div class="filter-area">
        <a-space direction="vertical" fill>
          <a-space :direction="isMobile ? 'vertical' : 'horizontal'" fill>
            <a-radio-group
              v-model="filter.gender"
              type="button"
              @change="handleFilterChange"
            >
              <a-radio :value="2">
                {{ $t('account.player.status.all') }}
              </a-radio>
              <a-radio :value="0">
                {{ $t('account.list.column.gender.male') }}
              </a-radio>
              <a-radio :value="1">
                {{ $t('account.list.column.gender.female') }}
              </a-radio>
            </a-radio-group>
            <a-input-search
              v-model="filter.keyword"
              :placeholder="$t('account.player.warp.placeholder')"
              :style="{ width: isMobile ? '100%' : '200px' }"
              @search="handleSearch"
              @press-enter="handleSearch"
            />
          </a-space>

          <div class="color-filter">
            <span class="label">
              {{ $t('account.player.selector.color') }}:
            </span>
            <div class="color-options">
              <div
                class="color-item"
                :class="{ active: filter.color === null }"
                @click="selectColor(null)"
              >
                {{ $t('account.player.selector.color.all') }}
              </div>
              <div
                v-for="(color, index) in colors"
                :key="index"
                class="color-item"
                :class="{ active: filter.color === index }"
                :style="{ backgroundColor: color }"
                @click="selectColor(index)"
              ></div>
            </div>
          </div>
        </a-space>
      </div>

      <!-- 列表区域 -->
      <div v-loading="loading" class="list-area">
        <div v-if="list.length === 0" class="empty-state">
          <a-empty :description="$t('account.player.selector.empty')" />
        </div>
        <div v-else class="grid-list">
          <div
            v-for="item in list"
            :key="item.id"
            class="grid-item"
            :class="{ active: selectedId === item.id }"
            @click="selectItem(item)"
          >
            <div class="item-image">
              <img :src="getIconUrl('item', item.id)" alt="" />
            </div>
            <div class="item-info">
              <div class="item-name" :title="item.name">{{ item.name }}</div>
              <div class="item-id">{{ item.id }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 分页区域 -->
      <div class="pagination-area">
        <a-pagination
          :total="total"
          :current="page"
          :page-size="pageSize"
          show-total
          :show-jumper="!isMobile"
          :simple="isMobile"
          @change="handlePageChange"
        />
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, reactive, watch, onMounted, onUnmounted } from 'vue';
  import { getStyles, InformationResult } from '@/api/information';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';

  const props = defineProps({
    visible: {
      type: Boolean,
      default: false,
    },
    type: {
      type: String,
      required: true, // 'hair' or 'face'
      validator: (value: string) => ['hair', 'face'].includes(value),
    },
    title: {
      type: String,
      default: '选择',
    },
    defaultId: {
      type: Number,
      default: null,
    },
  });

  const emit = defineEmits(['update:visible', 'select']);
  const { t } = useI18n();

  // 颜色定义 (对应 0-7)
  const colors = [
    '#000000', // 0: Black
    '#FF0000', // 1: Red
    '#FFA500', // 2: Orange
    '#FFFF00', // 3: Blonde/Yellow
    '#008000', // 4: Green
    '#0000FF', // 5: Blue
    '#800080', // 6: Purple
    '#A52A2A', // 7: Brown
  ];

  const loading = ref(false);
  const list = ref<InformationResult[]>([]);
  const total = ref(0);
  const page = ref(1);
  const pageSize = ref(100);
  const selectedId = ref<number | null>(null);
  const selectedItemData = ref<InformationResult | null>(null);

  const isMobile = ref(false);

  const checkScreen = () => {
    isMobile.value = window.innerWidth < 768;
  };

  const filter = reactive({
    gender: 2, // 0: Male, 1: Female, 2: All
    color: null as number | null,
    keyword: '',
  });

  const fetchData = async () => {
    loading.value = true;
    try {
      const res = await getStyles({
        type: props.type as 'hair' | 'face',
        keyword: filter.keyword,
        page: page.value,
        pageSize: pageSize.value,
        gender: filter.gender,
        color: filter.color,
      });

      // 后端已支持分页返回
      if (res.data && res.data.records) {
        list.value = res.data.records;
        total.value = res.data.totalRow;
      } else if (Array.isArray(res.data)) {
        // 兼容旧接口返回格式（如果是数组）
        // @ts-ignore
        list.value = res.data;
        // @ts-ignore
        if (res.data.length === pageSize.value) {
          total.value = page.value * pageSize.value + 1;
        } else {
          // @ts-ignore
          total.value = (page.value - 1) * pageSize.value + res.data.length;
        }
      }

      // 如果有默认ID且当前列表不包含该ID，尝试单独加载该ID的数据并插入到列表头部
      if (
        props.defaultId &&
        list.value.length > 0 &&
        !list.value.find((item) => item.id === props.defaultId)
      ) {
        // 只有在第一页且没有搜索关键字时才尝试插入，或者根据需求调整策略
        // 这里简单处理：如果不在当前页，尝试搜索该ID
        // 但为了不破坏当前浏览上下文，更好的做法可能是提示用户或者自动跳转（比较复杂）
        // 另一种方案：如果 defaultId 存在，且不在当前列表中，我们单独请求这个 ID 的详情
        // 然后把它临时加到列表最前面，或者高亮显示
        try {
          const detailRes = await getStyles({
            type: props.type as 'hair' | 'face',
            keyword: String(props.defaultId),
            page: 1,
            pageSize: 1,
            gender: 2, // 不限性别
            color: null, // 不限颜色
          });

          let targetItem = null;
          if (
            detailRes.data &&
            detailRes.data.records &&
            detailRes.data.records.length > 0
          ) {
            [targetItem] = detailRes.data.records;
          } else if (
            Array.isArray(detailRes.data) &&
            detailRes.data.length > 0
          ) {
            // @ts-ignore
            [targetItem] = detailRes.data;
          }

          if (targetItem && targetItem.id === props.defaultId) {
            // 将目标项插入到列表最前面，确保用户能看到
            list.value.unshift(targetItem);
            // 如果插入后超过了 pageSize，可以移除最后一个，或者保持原样
          }
        } catch (e) {
          // ignore
        }
      }
    } catch (error) {
      // Message.error('加载数据失败');
    } finally {
      loading.value = false;
    }
  };

  const handleSearch = () => {
    page.value = 1;
    fetchData();
  };

  const handleFilterChange = () => {
    page.value = 1;
    fetchData();
  };

  const selectColor = (index: number | null) => {
    filter.color = index;
    handleFilterChange();
  };

  const handlePageChange = (current: number) => {
    page.value = current;
    fetchData();
  };

  const selectItem = (item: InformationResult) => {
    selectedId.value = item.id;
    selectedItemData.value = item;
  };

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleOk = () => {
    if (selectedId.value) {
      emit('select', selectedId.value, selectedItemData.value);
      emit('update:visible', false);
    } else {
      Message.warning(t('account.player.selector.select'));
    }
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        if (props.defaultId) {
          selectedId.value = props.defaultId;
        }
        // 重置筛选并加载
        // filter.gender = 2;
        // filter.color = null;
        // filter.keyword = '';
        // page.value = 1;
        fetchData();
      }
    }
  );

  onMounted(() => {
    // fetchData(); // 初始不加载，打开弹窗时加载
    checkScreen();
    window.addEventListener('resize', checkScreen);
  });

  onUnmounted(() => {
    window.removeEventListener('resize', checkScreen);
  });
</script>

<style scoped lang="less">
  .selector-container {
    display: flex;
    flex-direction: column;
    height: 600px;
  }

  .filter-area {
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-border);
    margin-bottom: 16px;
  }

  .color-filter {
    display: flex;
    align-items: center;
    margin-top: 8px;
    flex-wrap: wrap;

    .label {
      margin-right: 8px;
    }

    .color-options {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .color-item {
      width: 24px;
      height: 24px;
      border-radius: 4px;
      cursor: pointer;
      border: 2px solid transparent;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;

      &:first-child {
        width: auto;
        padding: 0 8px;
        border: 1px solid var(--color-border);
      }

      &.active {
        border-color: rgb(var(--primary-6));
        box-shadow: 0 0 0 2px rgba(var(--primary-6), 0.2);
      }

      &:hover {
        opacity: 0.8;
      }
    }
  }

  .list-area {
    flex: 1;
    overflow-y: auto;

    .empty-state {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100%;
    }

    .grid-list {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
      gap: 12px;
    }

    .grid-item {
      border: 1px solid var(--color-border);
      border-radius: 4px;
      padding: 8px;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;

      &:hover {
        border-color: rgb(var(--primary-5));
        background-color: var(--color-fill-2);
      }

      &.active {
        border-color: rgb(var(--primary-6));
        background-color: rgb(var(--primary-1));
      }

      .item-image {
        width: 48px;
        height: 48px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        justify-content: center;

        img {
          max-width: 100%;
          max-height: 100%;
          object-fit: contain;
        }
      }

      .item-info {
        width: 100%;

        .item-name {
          font-size: 12px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          margin-bottom: 4px;
        }

        .item-id {
          font-size: 10px;
          color: var(--color-text-3);
        }
      }
    }
  }

  .pagination-area {
    padding-top: 16px;
    border-top: 1px solid var(--color-border);
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }
</style>
