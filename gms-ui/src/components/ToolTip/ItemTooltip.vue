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
          <span class="item-name">
            {{ item.name || $t('tooltip.unknownItem') }}
          </span>
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
  const itemDesc = ref(props.item.desc || '');
  const parsedDesc = computed(() => parseMapleText(itemDesc.value));

  const fetchItemDesc = async () => {
    // 如果 props 中已经有描述，直接使用
    if (props.item.desc) {
      itemDesc.value = props.item.desc;
      return;
    }

    // 检查缓存
    if (itemDescCache.has(props.item.itemId)) {
      itemDesc.value = itemDescCache.get(props.item.itemId) || '';
      return;
    }

    // 否则尝试异步获取
    try {
      const { data } = await informationSearch({
        types: ['eqp', 'consume', 'ins', 'etc', 'cash', 'pet'],
        filter: props.item.itemId.toString(),
        page: 1,
        pageSize: 1,
        fullMatch: true,
      });
      if (data && data.records && data.records.length > 0) {
        const record = data.records[0];
        if (record.desc) {
          itemDescCache.set(props.item.itemId, record.desc);
          itemDesc.value = record.desc;
        } else {
          // 如果没有描述，也缓存空字符串，避免重复请求
          itemDescCache.set(props.item.itemId, '');
          itemDesc.value = '';
        }
      } else {
        // 如果没有找到记录，也缓存空字符串
        itemDescCache.set(props.item.itemId, '');
        itemDesc.value = '';
      }
    } catch (e) {
      // ignore
    }
  };

  watch(
    () => props.item,
    () => {
      fetchItemDesc();
    },
    { immediate: true, deep: true }
  );
</script>

<script lang="ts">
  // 模块级缓存，所有组件实例共享
  const itemDescCache = new Map<number, string>();
</script>

<style scoped lang="less">
  .tooltip-container {
    width: 250px;
    background-color: rgba(0, 0, 0, 0.85);
    border-radius: 6px;
    padding: 10px;
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
        transform: scale(1.1); /* 放大图标 */
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
</style>
