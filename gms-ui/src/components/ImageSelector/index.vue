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
            <div class="search-group">
              <a-input-search
                v-model="filter.keyword"
                :placeholder="$t('account.player.warp.placeholder')"
                :style="{ width: isMobile ? '100%' : '200px' }"
                @search="handleSearch"
                @press-enter="handleSearch"
              />
              <a-button v-if="isMobile" @click="resetFilter">
                {{ $t('account.player.selector.reset') }}
              </a-button>
            </div>
            <a-button v-if="!isMobile" @click="resetFilter">
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
          <!-- 弹窗头部 -->
          <div class="popup-header">
            <span class="popup-title">
              {{
                isMobile ? selectedItemData?.name : hoveredItemData?.name || ''
              }}
            </span>
            <div
              class="close-btn"
              @click="
                isMobile ? (showMobileVariant = false) : (hoveredItemId = null)
              "
            >
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
                  <div class="variant-name">
                    {{ $t(`account.player.selector.color.${index % 9}`) }}
                  </div>
                  <div class="variant-id">
                    {{ variant.id }}
                    <span
                      class="color-dot"
                      :style="{ backgroundColor: colors[index % 9] }"
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

  // 颜色定义 (对应 0-8)
  const colors = [
    '#000000', // 0: Black
    '#FF0000', // 1: Red
    '#FFA500', // 2: Orange
    '#FFFF00', // 3: Blonde/Yellow
    '#008000', // 4: Green
    '#0000FF', // 5: Blue
    '#800080', // 6: Purple
    '#A52A2A', // 7: Brown
    '#FFFFFF', // 8: White
  ];

  const loading = ref(false);
  const list = ref<InformationResult[]>([]); // 当前页显示的数据
  const filteredData = ref<InformationResult[]>([]); // 经过筛选后的所有数据
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

  // 获取基础ID (用于定位和分组)
  const getBaseId = (id: number) => {
    if (props.type === 'face') {
      // 脸型：20000, 20100... 基础款为百位为0
      return Math.floor(id / 1000) * 1000 + (id % 100);
    }
    // 发型：30000, 30001... 基础款为个位为0
    return Math.floor(id / 10) * 10;
  };

  const updatePageList = () => {
    const start = (page.value - 1) * pageSize.value;
    const end = start + pageSize.value;
    list.value = filteredData.value.slice(start, end);
  };

  const locateDefaultId = () => {
    if (!props.defaultId) return;

    // 计算默认ID对应的基础ID (或者当前颜色下的ID)
    // 注意：如果当前筛选的颜色与默认ID的颜色不匹配，可能无法定位
    // 这里我们尝试找到最接近的匹配项

    // 简单起见，我们尝试在 filteredData 中查找 defaultId
    // 如果找不到，尝试查找 defaultId 的 BaseId (Color 0)

    let index = filteredData.value.findIndex(
      (item) => item.id === props.defaultId
    );

    if (index === -1) {
      // 如果找不到精确匹配，尝试找同款 (BaseId)
      const baseId = getBaseId(props.defaultId);
      // 注意：filteredData 中的 item 已经是经过颜色过滤的
      // 如果当前显示的是 Color 0，那么 item.id 就是 BaseId
      // 如果当前显示的是 Color 1，那么 item.id 是 VariantId

      // 我们比较 BaseId 是否相同
      index = filteredData.value.findIndex(
        (item) => getBaseId(item.id) === baseId
      );
    }

    if (index !== -1) {
      // 计算该项所在的页码
      page.value = Math.floor(index / pageSize.value) + 1;
      updatePageList();

      // 选中该项
      selectedId.value = props.defaultId; // 保持选中原始ID
      // 找到对应的数据对象
      selectedItemData.value = filteredData.value[index];

      hasLocatedDefaultId.value = true;
    }
  };

  const fetchData = async () => {
    loading.value = true;
    try {
      // 优化：一次性加载所有匹配的数据，在前端进行去重和分页
      // 这样可以解决“合并同类ID”导致的分页不准确问题
      const res = await getStyles({
        type: props.type as 'hair' | 'face',
        keyword: filter.keyword,
        page: 1,
        pageSize: 10000, // 假设足够大以获取所有数据
        gender: filter.gender,
        color: filter.color,
      });

      let rawList: InformationResult[] = [];
      if (res.data && res.data.records) {
        rawList = res.data.records;
      } else if (Array.isArray(res.data)) {
        // @ts-ignore
        rawList = res.data;
      }

      // 前端去重/分组逻辑
      const groups = new Map<number, InformationResult[]>();

      // 使用 for...of 循环替代 for...in 或 forEach
      for (let i = 0; i < rawList.length; i += 1) {
        const item = rawList[i];
        const baseId = getBaseId(item.id);
        if (!groups.has(baseId)) {
          groups.set(baseId, []);
        }
        groups.get(baseId)!.push(item);
      }

      const processed: InformationResult[] = [];

      // 遍历分组，选择代表性的一项
      // 使用 Array.from 转换 Map.entries()
      const groupEntries = Array.from(groups.entries());
      for (let i = 0; i < groupEntries.length; i += 1) {
        const [, items] = groupEntries[i];
        if (filter.color !== null) {
          // 如果选择了特定颜色，只显示该颜色的项
          const match = items.find((item) => {
            if (props.type === 'face')
              return Math.floor(item.id / 100) % 10 === filter.color;
            return item.id % 10 === filter.color;
          });
          if (match) {
            processed.push(match);
          }
        } else {
          // 如果未选择颜色（全部），优先显示基础色（0），如果没有则显示第一个
          const match = items.find((item) => {
            if (props.type === 'face')
              return Math.floor(item.id / 100) % 10 === 0;
            return item.id % 10 === 0;
          });
          if (match) {
            processed.push(match);
          } else if (items.length > 0) {
            processed.push(items[0]);
          }
        }
      }

      // 保持排序 (按ID)
      processed.sort((a, b) => a.id - b.id);

      filteredData.value = processed;
      total.value = processed.length;

      // 如果页码超出了范围，重置为1
      if ((page.value - 1) * pageSize.value >= total.value) {
        page.value = 1;
      }

      updatePageList();

      // 定位默认ID
      if (props.defaultId && !hasLocatedDefaultId.value) {
        locateDefaultId();
      }
    } catch (error) {
      Message.error(t('common.error.load'));
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

  const resetFilter = () => {
    filter.gender = 2;
    filter.color = null;
    filter.keyword = '';
    page.value = 1;
    fetchData();
  };

  const handlePageChange = (current: number) => {
    page.value = current;
    updatePageList(); // 前端分页，不需要重新请求
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
      max-height: 100%; /* 确保不超过父容器 */
    }
  }

  .filter-area {
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-border);
    margin-bottom: 16px;
    flex-shrink: 0; /* 防止被压缩 */
  }

  .search-group {
    display: flex;
    gap: 8px;
    width: 100%;
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
      max-height: 60vh; /* 限制最大高度 */
      background-color: var(--color-bg-2);
      padding: 16px;
    }

    .popup-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--color-border);
    }

    .popup-title {
      font-weight: 500;
      font-size: 14px;
    }

    .close-btn {
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
  .list-area::-webkit-scrollbar,
  .variant-popup::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }

  .list-area::-webkit-scrollbar-thumb,
  .variant-popup::-webkit-scrollbar-thumb {
    border-radius: 3px;
    background-color: var(--color-text-4);
  }

  .list-area::-webkit-scrollbar-track,
  .variant-popup::-webkit-scrollbar-track {
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
