<template>
  <div class="tooltip-container">
    <!-- 1. 头部：名称与标识 -->
    <div class="tooltip-header">
      <div class="item-title">
        <!-- Owner 居中显示 -->
        <div v-if="item.owner" class="item-owner">
          {{ $t('tooltip.owner') }}: {{ item.owner }}
        </div>

        <!-- 名称居左 -->
        <div class="item-name-row">
          <span
            class="item-name clickable-text"
            :title="$t('common.copy')"
            @click="copyText(itemName)"
          >
            {{ itemName || $t('tooltip.unknownItem') }}
          </span>
        </div>

        <!-- ID 显示 -->
        <div
          class="item-id-row clickable-text"
          :title="$t('common.copy')"
          @click="copyText(String(item.itemId))"
        >
          ID: {{ item.itemId }}
        </div>

        <!-- Flag 居中显示 -->
        <div v-if="flagText" class="item-flag">{{ flagText }}</div>

        <!-- 时间显示 -->
        <div v-if="timeText" class="item-time">{{ timeText }}</div>
      </div>
    </div>

    <div class="tooltip-divider"></div>

    <!-- 2. 图标与描述区域 -->
    <div class="tooltip-info-section">
      <!-- 左侧图标 -->
      <div class="item-icon-box">
        <img :src="iconUrl" class="item-icon" alt="icon" />
      </div>

      <!-- 右侧描述 -->
      <div class="item-desc-box">
        <!-- eslint-disable-next-line vue/no-v-html -->
        <div class="desc-text" v-html="parsedDesc"></div>
      </div>
    </div>

    <!-- 3. 底部信息：宿命剪刀 -->
    <div v-if="isKarma" class="tooltip-footer">
      <div class="tooltip-divider"></div>
      <div class="footer-row karma">
        {{ $t('tooltip.karma') }}
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
  import { computed, ref, watch } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import dayjs from 'dayjs';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import { parseMapleText, ItemFlags, hasFlag } from '@/utils/mapleStoryItem';
  import { informationSearch } from '@/api/information';

  const { t } = useI18n();

  const props = defineProps<{
    item: {
      itemId: number;
      quantity?: number;
      owner?: string;
      expiration?: number;
      name?: string;
      desc?: string;
      flag?: number;
    };
  }>();

  // **关键优化**: 使用 ref 存储动态获取的名称和描述
  const itemName = ref(props.item.name || '');
  const itemDesc = ref(props.item.desc || '');

  // 图标 URL
  const iconUrl = computed(() => getIconUrl('item', props.item.itemId));

  // Flag 判断
  const flag = computed(() => props.item.flag || 0);
  const isUntradeable = computed(() =>
    hasFlag(flag.value, ItemFlags.UNTRADEABLE)
  );
  const isLocked = computed(() => hasFlag(flag.value, ItemFlags.LOCK));
  const isKarma = computed(() => hasFlag(flag.value, ItemFlags.KARMA));
  const isAccountSharing = computed(() =>
    hasFlag(flag.value, ItemFlags.ACCOUNT_SHARING)
  );
  const isUnique = computed(() => false);

  // Flag 文本生成
  const flagText = computed(() => {
    const flags = [];
    if (isUntradeable.value) flags.push(t('tooltip.untradeable'));
    if (isUnique.value) flags.push(t('tooltip.unique'));
    if (isAccountSharing.value) flags.push(t('tooltip.accountSharing'));
    return flags.join(', ');
  });

  // 时间文本生成
  const timeText = computed(() => {
    if (!props.item.expiration || props.item.expiration <= 0) return '';
    const timeStr = dayjs(props.item.expiration).format('YYYY-MM-DD HH:mm:ss');
    if (isLocked.value) {
      return `${t('tooltip.lockUntil')} ${timeStr}`;
    }
    return `${t('tooltip.timeAvailable')} ${timeStr}`;
  });

  // 描述解析
  const parsedDesc = computed(() => parseMapleText(itemDesc.value));

  /**
   * @zh-CN 获取物品的名称和描述信息
   * @description 优先使用 props 传入的值。如果 props 中缺少，则通过网络请求获取并使用 Promise 缓存。
   */
  const fetchItemInfo = async () => {
    const { itemId, name, desc } = props.item;

    // 1. **立即响应**: 立即使用 props 传入的数据
    itemName.value = name || '';
    itemDesc.value = desc || '';

    // 2. **异步补充**: 如果数据不完整，则发起请求
    if (!name || !desc) {
      if (!itemId) return;

      let fetchPromise = itemInfoPromiseCache.get(itemId);
      if (!fetchPromise) {
        fetchPromise = informationSearch({
          types: ['eqp', 'consume', 'ins', 'etc', 'cash', 'pet'],
          filter: itemId.toString(),
          page: 1,
          pageSize: 1,
          fullMatch: true,
        })
          .then(({ data }) => {
            const record = data?.records?.[0];
            if (!record) {
              throw new Error(`找不到 ID 为 ${itemId} 的物品信息`);
            }
            // 返回一个包含名称和描述的对象
            return {
              name: record.name || '',
              desc: record.desc || '',
            };
          })
          .catch((err) => {
            itemInfoPromiseCache.delete(itemId);
            throw err;
          });
        itemInfoPromiseCache.set(itemId, fetchPromise);
      }

      try {
        const info = await fetchPromise;
        // 只有在 props 没有提供相应值时才更新
        if (!name) {
          itemName.value = info.name;
        }
        if (!desc) {
          itemDesc.value = info.desc;
        }
      } catch (e) {
        // 忽略错误
      }
    }
  };

  const copyText = async (text: string | undefined) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      Message.success(`${t('common.copy')} ${t('common.success')}: ${text}`);
    } catch (err) {
      Message.error(t('common.copy') + t('common.fail'));
    }
  };

  // **关键优化**: 只在 itemId 变化时触发数据获取
  watch(
    () => props.item.itemId,
    (newItemId) => {
      if (newItemId) {
        fetchItemInfo();
      }
    },
    { immediate: true }
  );
</script>

<script lang="ts">
  /**
   * @zh-CN 模块级缓存
   * @description 存储物品信息获取的 Promise，确保对同一个 itemId 的请求只发送一次。
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const itemInfoPromiseCache = new Map<
    number,
    Promise<{ name: string; desc: string }>
  >();
</script>

<style scoped lang="less">
  .tooltip-container {
    min-width: 260px;
    max-width: 320px;
    background-color: rgba(0, 0, 0, 0.85);
    border-radius: 6px;
    padding: 10px 10px 20px 10px;
    color: #fff;
    font-family: 'Arial', sans-serif;
    font-size: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    border: 1px solid #555;
    position: relative;
    user-select: none;
  }

  .tooltip-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 2px;

    .item-title {
      width: 100%;
      text-align: center;

      .item-owner {
        color: #ff9900;
        margin-bottom: 4px;
      }

      .item-name-row {
        text-align: left;
        margin-bottom: 4px;

        .item-name {
          font-weight: bold;
          font-size: 14px;
        }
      }

      .item-id-row {
        text-align: left;
        margin-bottom: 4px;
        font-size: 12px;
      }

      .item-flag {
        color: #ff9900;
        font-size: 12px;
        margin-bottom: 2px;
        text-align: center;
      }

      .item-time {
        font-size: 12px;
        margin-bottom: 2px;
        text-align: center;
      }
    }
  }

  .tooltip-info-section {
    display: flex;
    flex-direction: row;
    padding: 4px 0;

    .item-icon-box {
      width: 80px;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding-top: 6px;

      .item-icon {
        max-width: 64px;
        max-height: 64px;
        transform: scale(1.5); /* 放大图标 */
        transform-origin: center top; /* 调整放大基点 */
      }
    }

    .item-desc-box {
      flex: 1;
      padding-left: 10px;
      color: #fff;
      line-height: 1.4;

      .desc-text {
        white-space: pre-wrap;
      }
    }
  }

  .tooltip-divider {
    height: 1px;
    background: linear-gradient(to right, transparent, #777, transparent);
    margin: 6px 0;
  }

  .tooltip-footer {
    padding: 0 4px;
    text-align: center;

    .footer-row {
      margin-top: 4px;

      &.karma {
        color: #ff9900;
      }
    }
  }

  /* 可点击文本的样式 */
  .clickable-text {
    cursor: pointer;
    transition: all 0.2s;
  }

  .clickable-text:hover {
    text-shadow: 0 0 8px rgba(255, 255, 255, 0.8);
    color: #e6f7ff;
  }
</style>
