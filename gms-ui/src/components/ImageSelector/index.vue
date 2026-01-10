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
            <a-button @click="resetFilter">
              {{ $t('account.player.selector.reset') }}
            </a-button>
          </a-space>
        </a-space>
      </div>

      <!-- 列表区域 -->
      <div class="list-area">
        <a-spin :loading="loading" style="width: 100%; min-height: 100%">
          <div v-if="list.length === 0" class="empty-state">
            <a-empty :description="$t('account.player.selector.empty')" />
          </div>
          <div v-else class="grid-list">
            <div
              v-for="item in list"
              :key="item.id"
              class="grid-item"
              :class="{ active: selectedId === item.id }"
              @click="handleItemClick(item)"
              @mouseenter="handleItemMouseEnter($event, item)"
              @mouseleave="handleItemMouseLeave(item)"
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
        </a-spin>
      </div>

      <!-- 悬浮显示的变体选择器 (移出 grid-list，放在外层) -->
      <Teleport to="body">
        <!-- 移动端遮罩层 -->
        <div
          v-if="isMobile && showMobileVariant && selectedItemData"
          class="variant-popup-backdrop"
          @click="showMobileVariant = false"
        ></div>

        <div
          v-if="
            (!isMobile && hoveredItemId !== null) ||
            (isMobile && showMobileVariant && selectedItemData)
          "
          class="variant-popup"
          :style="popupStyle"
          @mouseenter="handlePopupMouseEnter"
          @mouseleave="handlePopupMouseLeave"
          @click.stop
        >
          <!-- 移动端关闭按钮和标题 -->
          <div v-if="isMobile" class="mobile-popup-header">
            <span class="mobile-popup-title">{{ selectedItemData?.name }}</span>
            <div class="mobile-close-btn" @click="showMobileVariant = false">
              <icon-close />
            </div>
          </div>

          <div class="variant-list">
            <a-tooltip
              v-for="(variant, index) in currentVariants"
              :key="variant.id"
              :content="`${variant.name} (${variant.id})`"
              position="top"
            >
              <div
                class="variant-option"
                :class="{ active: selectedId === variant.id }"
                @click="confirmVariant(variant)"
              >
                <div class="variant-image">
                  <img :src="getIconUrl('item', variant.id)" alt="" />
                </div>
                <div class="variant-info">
                  <div class="variant-name">{{ variant.name }}</div>
                  <div class="variant-id">
                    {{ variant.id }}
                    <span
                      class="color-dot"
                      :style="{ backgroundColor: colors[index % 8] }"
                    ></span>
                  </div>
                </div>
              </div>
            </a-tooltip>
          </div>
        </div>
      </Teleport>

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
  import { ref, reactive, watch, onMounted, onUnmounted, computed } from 'vue';
  import { getStyles, InformationResult } from '@/api/information';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import { Message } from '@arco-design/web-vue';
  import { IconClose } from '@arco-design/web-vue/es/icon';
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
  const hoveredItemId = ref<number | null>(null);
  const hoveredItemData = ref<InformationResult | null>(null);
  const showMobileVariant = ref(false);
  const popupPosition = reactive({
    top: 0,
    left: 0,
    bottom: undefined as number | undefined,
  });
  const isPopupHovered = ref(false);
  let hidePopupTimer: number | null = null;

  // 标记是否已经定位过初始ID
  const hasLocatedDefaultId = ref(false);

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

      // 过滤列表，只保留同类脸型/发型的第一个
      if (list.value.length > 0) {
        if (props.type === 'face') {
          // 脸型：保留 200xx, 210xx... 过滤掉 201xx, 202xx...
          // 假设颜色在百位，即 (id / 100) % 10 == 0
          list.value = list.value.filter(
            (item) => Math.floor(item.id / 100) % 10 === 0
          );
        } else {
          // 发型：保留 30000, 30010... 过滤掉 30001, 30002...
          list.value = list.value.filter((item) => item.id % 10 === 0);
        }
      }

      // 如果有默认ID且当前列表不包含该ID，尝试单独加载该ID的数据并插入到列表头部
      // 仅在首次加载且未定位过时执行
      if (
        props.defaultId &&
        !hasLocatedDefaultId.value &&
        list.value.length > 0 &&
        !list.value.find((item) => item.id === props.defaultId)
      ) {
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
            hasLocatedDefaultId.value = true; // 标记已定位
          }
        } catch (e) {
          // ignore
        }
      } else if (
        props.defaultId &&
        !hasLocatedDefaultId.value &&
        list.value.find((item) => item.id === props.defaultId)
      ) {
        // 如果默认ID已经在列表中，也标记为已定位，避免后续翻页重复触发逻辑（虽然上面的条件已经排除了这种情况，但为了逻辑完整性）
        hasLocatedDefaultId.value = true;
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

  // const selectColor = (index: number | null) => {
  //   filter.color = index;
  //   handleFilterChange();
  // };

  const resetFilter = () => {
    filter.gender = 2;
    filter.color = null;
    filter.keyword = '';
    page.value = 1;
    fetchData();
  };

  const handlePageChange = (current: number) => {
    page.value = current;
    fetchData();
  };

  // 生成变体ID列表
  const generateVariants = (baseItem: InformationResult) => {
    const baseId = baseItem.id;
    const variantList: InformationResult[] = [];

    if (props.type === 'face') {
      // 脸型规则：20000, 20100, 20200... 间隔100
      // 基础ID计算：去掉百位，保留其他位
      const rootId = Math.floor(baseId / 1000) * 1000 + (baseId % 100);
      for (let i = 0; i < 9; i += 1) {
        // 假设有9种颜色 (0-8)
        const variantId = rootId + i * 100;
        variantList.push({
          ...baseItem,
          id: variantId,
          name: baseItem.name, // 暂时复用，理想情况应查询后端
        });
      }
    } else {
      // 发型规则：30000~30007，尾数0~7
      // 基础ID计算：去掉个位
      const rootId = Math.floor(baseId / 10) * 10;
      for (let i = 0; i < 8; i += 1) {
        const variantId = rootId + i;
        variantList.push({
          ...baseItem,
          id: variantId,
          name: baseItem.name,
        });
      }
    }
    return variantList;
  };

  const currentVariants = computed(() => {
    if (isMobile.value) {
      return selectedItemData.value
        ? generateVariants(selectedItemData.value)
        : [];
    }
    return hoveredItemData.value ? generateVariants(hoveredItemData.value) : [];
  });

  const handleItemClick = (item: InformationResult) => {
    if (isMobile.value) {
      // 移动端：点击选中并显示变体弹窗
      selectedId.value = item.id;
      selectedItemData.value = item;
      showMobileVariant.value = true;
    } else {
      // PC端：点击选中
      selectedId.value = item.id;
      selectedItemData.value = item;
    }
  };

  const handleItemMouseEnter = (event: MouseEvent, item: InformationResult) => {
    if (!isMobile.value) {
      // 清除之前的隐藏定时器
      if (hidePopupTimer) {
        clearTimeout(hidePopupTimer);
        hidePopupTimer = null;
      }

      hoveredItemId.value = item.id;
      hoveredItemData.value = item;
      // 计算位置
      const target = event.currentTarget as HTMLElement;
      const {
        bottom: top,
        left,
        top: rectTop,
      } = target.getBoundingClientRect();

      // 默认显示在下方
      const finalTop = top;
      let finalLeft = left;

      popupPosition.bottom = undefined;

      // 检查底部空间
      const windowHeight = window.innerHeight;
      const popupHeight = 400; // 预估最大高度
      if (finalTop + popupHeight > windowHeight) {
        // 底部空间不足，显示在上方
        // finalTop = rectTop - popupHeight;
        popupPosition.bottom = windowHeight - rectTop;
        // 如果上方也不足，优先显示在空间大的一侧，或者调整高度
        // if (finalTop < 0) {
        //   finalTop = 10; // 贴顶
        //   // 此时可能需要限制高度，css中已有 max-height
        // }
      } else {
        popupPosition.top = finalTop;
      }

      // 检查右侧空间
      const windowWidth = window.innerWidth;
      const popupWidth = 240;
      if (finalLeft + popupWidth > windowWidth) {
        finalLeft = windowWidth - popupWidth - 10; // 贴右边，留点间隙
      }

      // popupPosition.top = finalTop;
      popupPosition.left = finalLeft;
    }
  };

  const handleItemMouseLeave = (item: InformationResult) => {
    if (!isMobile.value) {
      // 延迟隐藏，以便鼠标可以移动到悬浮窗上
      hidePopupTimer = window.setTimeout(() => {
        if (!isPopupHovered.value && hoveredItemId.value === item.id) {
          hoveredItemId.value = null;
          hoveredItemData.value = null;
        }
      }, 100);
    }
  };

  const handlePopupMouseEnter = () => {
    isPopupHovered.value = true;
    // 清除隐藏定时器，防止鼠标在悬浮窗上时被隐藏
    if (hidePopupTimer) {
      clearTimeout(hidePopupTimer);
      hidePopupTimer = null;
    }
  };
  const handlePopupMouseLeave = () => {
    isPopupHovered.value = false;
    hoveredItemId.value = null;
    hoveredItemData.value = null;
  };

  const popupStyle = computed(() => {
    if (isMobile.value) {
      return {}; // 移动端使用 CSS fixed 居中
    }
    const style: Record<string, string> = {
      left: `${popupPosition.left}px`,
      position: 'fixed', // PC端也用 fixed，配合计算出的坐标
    };
    if (popupPosition.bottom !== undefined) {
      style.bottom = `${popupPosition.bottom}px`;
    } else {
      style.top = `${popupPosition.top}px`;
    }
    return style;
  });

  const confirmVariant = (item: InformationResult) => {
    selectedId.value = item.id;
    selectedItemData.value = item;
    showMobileVariant.value = false; // 关闭移动端弹窗
    // 也可以选择直接关闭主弹窗并确认
    emit('select', selectedId.value, selectedItemData.value);
    emit('update:visible', false);
  };

  const handleCancel = () => {
    emit('update:visible', false);
    showMobileVariant.value = false;
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
          hasLocatedDefaultId.value = false; // 重置定位标记，以便下次打开时重新定位
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
    /* 移动端高度自适应，但不超过屏幕 */
    @media (max-width: 768px) {
      height: calc(100vh - 100px);
    }
  }

  .filter-area {
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-border);
    margin-bottom: 16px;
    flex-shrink: 0; /* 防止被压缩 */
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
    /* 增加内边距，防止滚动条遮挡内容 */
    padding-right: 4px;
    min-height: 0; /* 关键：允许flex子项收缩 */

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
      /* position: relative;  移除 relative，因为悬浮窗现在在外部 */

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

  /* 悬浮变体选择器样式 - 移到外层 */
  .variant-popup-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    z-index: 9998;
  }

  .variant-popup {
    position: fixed; /* 始终使用 fixed 定位 */
    background-color: var(--color-bg-popup);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    padding: 8px;
    z-index: 9999; /* 确保在最顶层 */
    width: 240px; /* 调整宽度 */
    max-height: 400px;
    overflow-y: auto;

    /* 移动端适配：点击显示，且位置调整 */
    @media (max-width: 768px) {
      top: 50% !important; /* 强制居中 */
      left: 50% !important;
      transform: translate(-50%, -50%);
      width: 280px;
      background-color: var(--color-bg-2);
      padding: 16px;
    }

    .mobile-popup-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--color-border);
    }

    .mobile-popup-title {
      font-weight: 500;
      font-size: 14px;
    }

    .mobile-close-btn {
      cursor: pointer;
      padding: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--color-text-2);

      &:hover {
        color: var(--color-text-1);
        background-color: var(--color-fill-2);
        border-radius: 50%;
      }
    }

    .variant-list {
      display: flex;
      flex-direction: column; /* 纵向排列 */
      gap: 4px;
    }

    .variant-option {
      display: flex;
      align-items: center;
      padding: 4px;
      border: 1px solid transparent;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;

      &:hover {
        background-color: var(--color-fill-3);
      }

      &.active {
        border-color: rgb(var(--primary-6));
        background-color: rgb(var(--primary-1));
      }

      .variant-image {
        width: 40px;
        height: 40px;
        margin-right: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;

        img {
          max-width: 100%;
          max-height: 100%;
          object-fit: contain;
        }
      }

      .variant-info {
        flex: 1;
        overflow: hidden;
        text-align: left;

        .variant-name {
          font-size: 12px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .variant-id {
          font-size: 10px;
          color: var(--color-text-3);
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .color-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          display: inline-block;
          border: 1px solid rgba(0, 0, 0, 0.1);
        }
      }
    }
  }

  /* 自定义滚动条样式 */
  .list-area::-webkit-scrollbar {
    width: 6px;
    height: 6px;
    display: none;
  }

  .list-area:hover::-webkit-scrollbar {
    display: block;
  }

  .list-area::-webkit-scrollbar-thumb {
    border-radius: 3px;
    background-color: var(--color-text-4);
  }

  .list-area::-webkit-scrollbar-track {
    background-color: transparent;
  }

  .pagination-area {
    padding-top: 16px;
    border-top: 1px solid var(--color-border);
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
    flex-shrink: 0; /* 防止被压缩 */
  }
</style>
