<template>
  <div class="tooltip-container">
    <!-- 1. 头部：名称与标识 -->
    <div class="tooltip-header">
      <div class="item-title">
        <!-- Owner 居中显示 -->
        <div v-if="normalizedItem.owner" class="item-owner">
          {{ $t('tooltip.owner') }}: {{ normalizedItem.owner }}
        </div>

        <!-- 名称居左，Level 在右侧 -->
        <div class="item-name-row">
          <span
            class="item-name clickable-text"
            :title="$t('common.copy')"
            @click="copyText(normalizedItem.name)"
          >
            {{ normalizedItem.name || $t('tooltip.unknownItem') }}
          </span>
          <span
            v-if="normalizedItem.level && normalizedItem.level > 0"
            class="item-upgrade-level"
            >(+{{ normalizedItem.level }})</span
          >
        </div>

        <!-- ID 显示 -->
        <div
          class="item-id-row clickable-text"
          :title="$t('common.copy')"
          @click="copyText(String(normalizedItem.itemId))"
        >
          ID: {{ normalizedItem.itemId }}
        </div>

        <!-- Flag 居中显示 -->
        <div v-if="flagText" class="item-flag">{{ flagText }}</div>

        <!-- 时间显示 -->
        <div v-if="timeText" class="item-time">{{ timeText }}</div>
      </div>
    </div>

    <div class="tooltip-divider"></div>

    <!-- 2. 图标与穿戴要求区域 -->
    <div class="tooltip-info-section">
      <!-- 左侧图标 -->
      <div class="item-icon-box">
        <img :src="iconUrl" class="item-icon" alt="icon" />
      </div>

      <!-- 右侧穿戴要求 -->
      <div class="item-reqs">
        <div class="req-row">
          <span class="req-label">{{ $t('tooltip.reqLevel') }} :</span>
          <span class="req-val">{{ reqLevel }}</span>
          <span class="req-spacer"></span>
          <span class="req-label">{{ $t('tooltip.reqPop') }} :</span>
          <span class="req-val">{{ reqPop }}</span>
        </div>
        <div class="req-row">
          <span class="req-label">{{ $t('tooltip.reqStr') }} :</span>
          <span class="req-val">{{ reqStr }}</span>
          <span class="req-spacer"></span>
          <span class="req-label">{{ $t('tooltip.reqDex') }} :</span>
          <span class="req-val">{{ reqDex }}</span>
        </div>
        <div class="req-row">
          <span class="req-label">{{ $t('tooltip.reqInt') }} :</span>
          <span class="req-val">{{ reqInt }}</span>
          <span class="req-spacer"></span>
          <span class="req-label">{{ $t('tooltip.reqLuk') }} :</span>
          <span class="req-val">{{ reqLuk }}</span>
        </div>
        <div class="req-row">
          <span class="req-label">{{ $t('tooltip.itemLevel') }} :</span>
          <span class="req-val">{{ normalizedItem.itemLevel || 0 }}</span>
          <span class="req-spacer"></span>
          <span class="req-label">{{ $t('tooltip.itemExp') }} :</span>
          <span class="req-val">{{ normalizedItem.itemExp || 0 }}</span>
        </div>
      </div>
    </div>

    <!-- 职业要求 -->
    <div class="job-reqs">
      <span :class="{ active: canWearJob(0) }">
        {{ $t('tooltip.job.beginner') }}
      </span>
      <span :class="{ active: canWearJob(1) }">
        {{ $t('tooltip.job.warrior') }}
      </span>
      <span :class="{ active: canWearJob(2) }">
        {{ $t('tooltip.job.magician') }}
      </span>
      <span :class="{ active: canWearJob(4) }">
        {{ $t('tooltip.job.bowman') }}
      </span>
      <span :class="{ active: canWearJob(8) }">
        {{ $t('tooltip.job.thief') }}
      </span>
      <span :class="{ active: canWearJob(16) }">
        {{ $t('tooltip.job.pirate') }}
      </span>
    </div>

    <div class="tooltip-divider"></div>

    <!-- 3. 属性区域 -->
    <div class="tooltip-stats">
      <!-- 装备类型 -->
      <div class="stat-row">
        <span class="stat-label">{{ $t('tooltip.category') }} :</span>
        <span class="stat-val">{{ categoryName }}</span>
      </div>

      <!-- 属性列表 -->
      <div v-if="normalizedItem.str > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.str') }} :</span>
        <span class="stat-val">+{{ normalizedItem.str }}</span>
      </div>
      <div v-if="normalizedItem.dex > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.dex') }} :</span>
        <span class="stat-val">+{{ normalizedItem.dex }}</span>
      </div>
      <div v-if="normalizedItem.int > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.int') }} :</span>
        <span class="stat-val">+{{ normalizedItem.int }}</span>
      </div>
      <div v-if="normalizedItem.luk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.luk') }} :</span>
        <span class="stat-val">+{{ normalizedItem.luk }}</span>
      </div>
      <div v-if="normalizedItem.hp > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.hp') }} :</span>
        <span class="stat-val">+{{ normalizedItem.hp }}</span>
      </div>
      <div v-if="normalizedItem.mp > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.mp') }} :</span>
        <span class="stat-val">+{{ normalizedItem.mp }}</span>
      </div>
      <div v-if="normalizedItem.watk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.watk') }} :</span>
        <span class="stat-val">+{{ normalizedItem.watk }}</span>
      </div>
      <div v-if="normalizedItem.matk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.matk') }} :</span>
        <span class="stat-val">+{{ normalizedItem.matk }}</span>
      </div>
      <div v-if="normalizedItem.wdef > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.wdef') }} :</span>
        <span class="stat-val">+{{ normalizedItem.wdef }}</span>
      </div>
      <div v-if="normalizedItem.mdef > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.mdef') }} :</span>
        <span class="stat-val">+{{ normalizedItem.mdef }}</span>
      </div>
      <div v-if="normalizedItem.acc > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.acc') }} :</span>
        <span class="stat-val">+{{ normalizedItem.acc }}</span>
      </div>
      <div v-if="normalizedItem.avoid > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.avoid') }} :</span>
        <span class="stat-val">+{{ normalizedItem.avoid }}</span>
      </div>
      <div v-if="normalizedItem.hands > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.hands') }} :</span>
        <span class="stat-val">+{{ normalizedItem.hands }}</span>
      </div>
      <div v-if="normalizedItem.speed > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.speed') }} :</span>
        <span class="stat-val">+{{ normalizedItem.speed }}</span>
      </div>
      <div v-if="normalizedItem.jump > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.jump') }} :</span>
        <span class="stat-val">+{{ normalizedItem.jump }}</span>
      </div>

      <!-- 防滑/防寒 -->
      <div v-if="isSpikes" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.spikes') }}</span>
        <span class="stat-val"></span>
      </div>
      <div v-if="isCold" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.cold') }}</span>
        <span class="stat-val"></span>
      </div>

      <!-- 升级次数 -->
      <div
        v-if="normalizedItem.upgradeSlots && normalizedItem.upgradeSlots > 0"
        class="stat-row"
      >
        <span class="stat-label">{{ $t('tooltip.upgradeSlots') }} :</span>
        <span class="stat-val">{{ normalizedItem.upgradeSlots }}</span>
      </div>

      <!-- 金锤子次数 -->
      <div
        v-if="normalizedItem.vicious && normalizedItem.vicious > 0"
        class="stat-row"
      >
        <span class="stat-label">{{ $t('tooltip.hammerSlots') }} :</span>
        <span class="stat-val">{{ normalizedItem.vicious }}</span>
      </div>
    </div>

    <!-- 4. 描述区域 -->
    <div v-if="itemDesc" class="tooltip-desc">
      <div class="tooltip-divider"></div>
      <!-- eslint-disable-next-line vue/no-v-html -->
      <div class="desc-text" v-html="parsedDesc"></div>
    </div>

    <!-- 5. 底部信息：宿命剪刀 -->
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
  import {
    parseMapleText,
    ItemFlags,
    hasFlag,
    getEquipCategory,
  } from '@/utils/mapleStoryItem';
  import { getEquInitialInfo } from '@/api/player';
  import { informationSearch } from '@/api/information';

  const { t } = useI18n();

  // 定义 Props，接收新旧两种可能的 item 结构
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const props = defineProps<{
    item: any;
  }>();

  // **关键修复**: 创建一个计算属性，将传入的 item 对象标准化
  const normalizedItem = computed(() => {
    const raw = props.item || {};
    return {
      itemId: raw.id || raw.itemId,
      quantity: raw.qty || raw.quantity,
      name: raw.nm || raw.name,
      desc: raw.desc,
      owner: raw.own || raw.owner,
      expiration: raw.exp || raw.expiration,
      sn: raw.sn,
      petId: raw.pid || raw.petId,
      str: raw.s || raw.str || 0,
      dex: raw.d || raw.dex || 0,
      int: raw.i || raw.int || 0,
      luk: raw.l || raw.luk || 0,
      hp: raw.h || raw.hp || 0,
      mp: raw.m || raw.mp || 0,
      watk: raw.wa || raw.watk || 0,
      matk: raw.ma || raw.matk || 0,
      wdef: raw.wd || raw.wdef || 0,
      mdef: raw.md || raw.mdef || 0,
      acc: raw.ac || raw.acc || 0,
      avoid: raw.av || raw.avoid || 0,
      hands: raw.hd || raw.hands || 0,
      speed: raw.sp || raw.speed || 0,
      jump: raw.jp || raw.jump || 0,
      upgradeSlots: raw.us || raw.upgradeSlots || 0,
      level: raw.lv || raw.level || 0,
      itemLevel: raw.il || raw.itemLevel || 0,
      itemExp: raw.itemExp || 0,
      flag: raw.f || raw.flag || 0,
      vicious: raw.vc || raw.vicious || 0,
      reqLevel: raw.reqLevel, // **关键优化**: 直接传递，不做 `|| 0` 处理
      reqJob: raw.reqJob,
      reqStr: raw.reqStr,
      reqDex: raw.reqDex,
      reqInt: raw.reqInt,
      reqLuk: raw.reqLuk,
      reqPop: raw.reqPop,
    };
  });

  // 图标 URL
  const iconUrl = computed(() =>
    getIconUrl('item', normalizedItem.value.itemId)
  );

  // 类别名称
  const categoryName = computed(() => {
    const cat = getEquipCategory(normalizedItem.value.itemId);
    return t(`tooltip.category.${cat}`);
  });

  // Flag 判断
  const flag = computed(() => normalizedItem.value.flag);
  const isUntradeable = computed(() =>
    hasFlag(flag.value, ItemFlags.UNTRADEABLE)
  );
  const isLocked = computed(() => hasFlag(flag.value, ItemFlags.LOCK));
  const isKarma = computed(() => hasFlag(flag.value, ItemFlags.KARMA));
  const isAccountSharing = computed(() =>
    hasFlag(flag.value, ItemFlags.ACCOUNT_SHARING)
  );
  const isSpikes = computed(() => hasFlag(flag.value, ItemFlags.SPIKES));
  const isCold = computed(() => hasFlag(flag.value, ItemFlags.COLD));
  const isUnique = computed(() => false); // 暂无 Unique 逻辑

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
    if (
      !normalizedItem.value.expiration ||
      normalizedItem.value.expiration <= 0
    ) {
      return '';
    }
    const timeStr = dayjs(normalizedItem.value.expiration).format(
      'YYYY-MM-DD HH:mm:ss'
    );
    if (isLocked.value) {
      return `${t('tooltip.lockUntil')} ${timeStr}`;
    }
    return `${t('tooltip.timeAvailable')} ${timeStr}`;
  });

  // 描述解析
  const itemDesc = ref(normalizedItem.value.desc || '');
  const parsedDesc = computed(() => parseMapleText(itemDesc.value));

  // 穿戴要求
  const reqLevel = ref(0);
  const reqStr = ref(0);
  const reqDex = ref(0);
  const reqInt = ref(0);
  const reqLuk = ref(0);
  const reqPop = ref(0);
  const reqJob = ref(0);

  /**
   * @zh-CN 获取装备的静态穿戴要求信息
   * @description 优先使用 props 传入的值。如果 props 中缺少该值，则通过网络请求获取并使用缓存。
   */
  const fetchInitialInfo = async () => {
    const { itemId } = normalizedItem.value;
    if (!itemId) return;

    // **关键优化**: 检查 props 中是否已定义穿戴要求。
    // `undefined` 表示该字段未在传入的 item 对象中提供。
    if (normalizedItem.value.reqLevel !== undefined) {
      return; // 如果 props 中有值（即使是 0），则直接使用，不发起请求
    }

    // 先从缓存获取 Promise，不存在则创建新的
    let fetchPromise = equipInfoPromiseCache.get(itemId);
    if (!fetchPromise) {
      fetchPromise = getEquInitialInfo(itemId)
        .then(({ data }) => {
          if (!data) {
            throw new Error(`找不到 ID 为 ${itemId} 的装备初始信息`);
          }
          return data;
        })
        .catch((err) => {
          equipInfoPromiseCache.delete(itemId);
          throw err;
        });
      equipInfoPromiseCache.set(itemId, fetchPromise);
    }

    // 等待 Promise 完成并更新 ref
    try {
      const equipData = await fetchPromise;
      reqLevel.value = equipData.reqLevel || 0;
      reqStr.value = equipData.reqSTR || 0;
      reqDex.value = equipData.reqDEX || 0;
      reqInt.value = equipData.reqINT || 0;
      reqLuk.value = equipData.reqLUK || 0;
      reqPop.value = equipData.reqPOP || 0;
      reqJob.value = equipData.reqJob || 0;
    } catch (e) {
      // 忽略错误
    }
  };

  /**
   * @zh-CN 获取装备的描述信息
   * @description 优先使用 props 传入的值。如果 props 中缺少，则通过网络请求获取并使用缓存。
   */
  const fetchItemDesc = async () => {
    const { desc, itemId } = normalizedItem.value;
    if (desc) {
      return; // 如果 props 中有值，直接使用
    }
    if (!itemId) return;

    let fetchPromise = equipDescPromiseCache.get(itemId);
    if (!fetchPromise) {
      fetchPromise = informationSearch({
        types: ['eqp'],
        filter: itemId.toString(),
        page: 1,
        pageSize: 1,
        fullMatch: true,
      })
        .then(({ data }) => {
          const { records } = data || {};
          return records?.[0]?.desc || '';
        })
        .catch((err) => {
          equipDescPromiseCache.delete(itemId);
          throw err;
        });
      equipDescPromiseCache.set(itemId, fetchPromise);
    }

    try {
      itemDesc.value = await fetchPromise;
    } catch (e) {
      itemDesc.value = '';
    }
  };

  // 职业判断逻辑
  const canWearJob = (jobFlag: number) => {
    if (reqJob.value === 0 || reqJob.value === -1) return true;
    if (jobFlag === 0) return false;
    // eslint-disable-next-line no-bitwise
    return (reqJob.value & jobFlag) !== 0;
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

  // **关键优化**: 侦听器现在负责同步更新数据和触发异步获取
  watch(
    () => normalizedItem.value,
    (currentItem) => {
      if (!currentItem.itemId) return;

      // 1. **立即响应**: 立即使用 props 传入的所有数据更新视图
      itemDesc.value = currentItem.desc || '';
      reqLevel.value = currentItem.reqLevel ?? 0; // 使用 ?? 确保 undefined 被转为 0
      reqStr.value = currentItem.reqStr ?? 0;
      reqDex.value = currentItem.reqDex ?? 0;
      reqInt.value = currentItem.reqInt ?? 0;
      reqLuk.value = currentItem.reqLuk ?? 0;
      reqPop.value = currentItem.reqPop ?? 0;
      reqJob.value = currentItem.reqJob ?? 0;

      // 2. **异步补充**: 如果数据不完整，则在后台发起请求补充
      fetchInitialInfo();
      fetchItemDesc();
    },
    { immediate: true, deep: true } // deep is needed to detect changes within the item object
  );
</script>

<script lang="ts">
  /**
   * @zh-CN 模块级缓存
   * @description 将 Promise 实例在所有组件间共享。
   * 这确保了对于同一个 itemId，网络请求只会被触发一次，后续所有请求都会等待同一个 Promise 的结果。
   * 这是解决并发请求和竞态条件的核心。
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const equipInfoPromiseCache = new Map<number, Promise<any>>();
  const equipDescPromiseCache = new Map<number, Promise<string>>();
</script>

<style scoped lang="less">
  .tooltip-container {
    display: flex;
    flex-direction: column;
    min-width: 270px;
    width: fit-content; /* 适应内容宽度 */
    max-width: none;
    background-color: rgba(0, 0, 0, 0.85);
    border-radius: 6px;
    padding: 10px 0 20px 10px;
    color: #fff;
    font-family: 'Arial', sans-serif;
    font-size: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    border: 1px solid #555;
    position: relative;
    user-select: none;
  }

  /*
    关键布局逻辑：
    1. .job-reqs 保持 nowrap，作为撑开宽度的基准。
    2. 其他所有直接子元素 (.tooltip-header, .tooltip-info-section, .tooltip-stats, .tooltip-desc, .tooltip-footer)
       设置 width: 0 (或极小值) 和 min-width: 100%。
       这使得它们不会主动撑开父容器，而是跟随父容器的宽度（由 job-reqs 和 min-width 决定）。
       同时 min-width: 100% 保证它们占满当前宽度。
  */

  .tooltip-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 2px;
    width: 0;
    min-width: 100%;

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
        white-space: normal; /* 允许换行 */
        word-break: break-word; /* 允许长单词换行 */

        .item-name {
          font-weight: bold;
          font-size: 14px;
        }

        .item-upgrade-level {
          margin-left: 4px;
          white-space: nowrap;
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
    width: 0;
    min-width: 100%;

    .item-icon-box {
      width: 80px;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding-top: 6px;
      flex-shrink: 0; /* 图标不压缩 */

      .item-icon {
        max-width: 64px;
        max-height: 64px;
        transform: scale(1.5);
        transform-origin: center top;
      }
    }

    .item-reqs {
      flex: 1;
      display: flex;
      flex-wrap: wrap;
      align-content: flex-start;
      padding-left: 10px;

      .req-row {
        width: 100%;
        margin-bottom: 0;
        line-height: 1.2;
        font-size: 11px;
        display: flex;
        justify-content: flex-start;

        &.full-width {
          width: 100%;
        }

        .req-label {
          color: #fff;
          margin-right: 4px;
          text-align: right;
          min-width: 40px;
        }

        .req-val {
          color: #fff;
          text-align: left;
          min-width: 30px;
        }

        .req-spacer {
          width: 15px;
        }
      }
    }
  }

  .job-reqs {
    display: flex;
    justify-content: center;
    gap: 8px;
    margin-bottom: 6px;
    font-size: 11px;
    white-space: nowrap; /* 强制不换行，撑开宽度 */
    flex-wrap: nowrap;

    span {
      color: #ff4d4f;

      &.active {
        color: #fff;
      }
    }
  }

  .tooltip-divider {
    height: 1px;
    background: linear-gradient(to right, transparent, #777, transparent);
    margin: 6px 0;
  }

  .tooltip-stats {
    padding: 0 4px;
    width: 0;
    min-width: 100%;

    .stat-row {
      margin-bottom: 0;
      line-height: 1.2;
      color: #fff;
      display: flex;

      .stat-label {
        width: 100px;
        text-align: right;
        margin-right: 8px;
        flex-shrink: 0; /* 标签不压缩 */
      }

      .stat-val {
        text-align: left;
        white-space: normal;
        word-break: break-all;
      }

      &.karma {
        color: #ff9900;
        margin-top: 4px;
      }
    }
  }

  .tooltip-desc {
    padding: 4px;
    color: #fff;
    line-height: 1.4;
    width: 0; /* 关键：不撑开父容器 */
    min-width: 100%; /* 关键：占满父容器 */

    .desc-text {
      white-space: pre-wrap;
      word-break: break-word;
    }
  }

  .tooltip-footer {
    padding: 0 4px;
    text-align: center;
    width: 0;
    min-width: 100%;

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
