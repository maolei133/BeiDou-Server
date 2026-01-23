<template>
  <div class="tooltip-container">
    <!-- 1. 头部：名称与标识 -->
    <div class="tooltip-header">
      <div class="item-title">
        <!-- Owner 居中显示 -->
        <div v-if="item.owner" class="item-owner">
          {{ $t('tooltip.owner') }}: {{ item.owner }}
        </div>

        <!-- 名称居左，Level 在右侧 -->
        <div class="item-name-row">
          <span
            class="item-name clickable-text"
            :title="$t('common.copy')"
            @click="copyText(item.name)"
          >
            {{ item.name || $t('tooltip.unknownItem') }}
          </span>
          <span v-if="item.level && item.level > 0" class="item-upgrade-level"
            >(+{{ item.level }})</span
          >
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
          <span class="req-val">{{ item.itemLevel || 0 }}</span>
          <span class="req-spacer"></span>
          <span class="req-label">{{ $t('tooltip.itemExp') }} :</span>
          <span class="req-val">{{ item.itemExp || 0 }}</span>
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
      <div v-if="item.str > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.str') }} :</span>
        <span class="stat-val">+{{ item.str }}</span>
      </div>
      <div v-if="item.dex > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.dex') }} :</span>
        <span class="stat-val">+{{ item.dex }}</span>
      </div>
      <div v-if="itemInt > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.int') }} :</span>
        <span class="stat-val">+{{ itemInt }}</span>
      </div>
      <div v-if="item.luk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.luk') }} :</span>
        <span class="stat-val">+{{ item.luk }}</span>
      </div>
      <div v-if="item.hp > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.hp') }} :</span>
        <span class="stat-val">+{{ item.hp }}</span>
      </div>
      <div v-if="item.mp > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.mp') }} :</span>
        <span class="stat-val">+{{ item.mp }}</span>
      </div>
      <div v-if="item.watk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.watk') }} :</span>
        <span class="stat-val">+{{ item.watk }}</span>
      </div>
      <div v-if="item.matk > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.matk') }} :</span>
        <span class="stat-val">+{{ item.matk }}</span>
      </div>
      <div v-if="item.wdef > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.wdef') }} :</span>
        <span class="stat-val">+{{ item.wdef }}</span>
      </div>
      <div v-if="item.mdef > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.mdef') }} :</span>
        <span class="stat-val">+{{ item.mdef }}</span>
      </div>
      <div v-if="item.acc > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.acc') }} :</span>
        <span class="stat-val">+{{ item.acc }}</span>
      </div>
      <div v-if="item.avoid > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.avoid') }} :</span>
        <span class="stat-val">+{{ item.avoid }}</span>
      </div>
      <div v-if="item.hands > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.hands') }} :</span>
        <span class="stat-val">+{{ item.hands }}</span>
      </div>
      <div v-if="item.speed > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.speed') }} :</span>
        <span class="stat-val">+{{ item.speed }}</span>
      </div>
      <div v-if="item.jump > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.jump') }} :</span>
        <span class="stat-val">+{{ item.jump }}</span>
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
      <div v-if="item.upgradeSlots > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.upgradeSlots') }} :</span>
        <span class="stat-val">{{ item.upgradeSlots }}</span>
      </div>

      <!-- 金锤子次数 -->
      <div v-if="item.vicious && item.vicious > 0" class="stat-row">
        <span class="stat-label">{{ $t('tooltip.hammerSlots') }} :</span>
        <span class="stat-val">{{ item.vicious }}</span>
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

  // 定义 Props，接收 ItemInfoRtnDTO 结构的数据
  const props = defineProps<{
    item: {
      itemId: number;
      quantity?: number;
      owner?: string;
      expiration?: number;
      name?: string;
      desc?: string;
      sn?: number;
      str?: number;
      dex?: number;
      int?: number; // 兼容 int
      // eslint-disable-next-line camelcase, no-underscore-dangle
      int_?: number; // 兼容 int_
      inte?: number; // 统一为 inte
      luk?: number;
      hp?: number;
      mp?: number;
      watk?: number;
      matk?: number;
      wdef?: number;
      mdef?: number;
      acc?: number;
      avoid?: number;
      hands?: number;
      speed?: number;
      jump?: number;
      upgradeSlots?: number;
      vicious?: number; // 金锤子次数
      level?: number; // 强化等级 (+N)
      itemLevel?: number; // 道具成长等级
      itemExp?: number; // 道具经验
      flag?: number;
      // 穿戴要求 (后端扩展字段)
      reqLevel?: number;
      reqJob?: number;
      reqStr?: number;
      reqDex?: number;
      reqInt?: number;
      reqLuk?: number;
      reqPop?: number;
    };
  }>();

  // 计算属性：获取智力值，优先取 inte，其次 int，最后 int_
  const itemInt = computed(() => {
    if (props.item.inte !== undefined) return props.item.inte;
    if (props.item.int !== undefined) return props.item.int;
    // eslint-disable-next-line camelcase, no-underscore-dangle
    if (props.item.int_ !== undefined) return props.item.int_;
    return 0;
  });

  // 图标 URL
  const iconUrl = computed(() => getIconUrl('item', props.item.itemId));

  // 类别名称
  const categoryName = computed(() => {
    const cat = getEquipCategory(props.item.itemId);
    return t(`tooltip.category.${cat}`);
  });

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

  // 穿戴要求
  const reqLevel = ref(0);
  const reqStr = ref(0);
  const reqDex = ref(0);
  const reqInt = ref(0);
  const reqLuk = ref(0);
  const reqPop = ref(0);
  const reqJob = ref(0);

  const fetchInitialInfo = async () => {
    // 如果 props 中已经有数据，直接使用
    if (props.item.reqLevel !== undefined) {
      reqLevel.value = props.item.reqLevel || 0;
      reqStr.value = props.item.reqStr || 0;
      reqDex.value = props.item.reqDex || 0;
      reqInt.value = props.item.reqInt || 0;
      reqLuk.value = props.item.reqLuk || 0;
      reqPop.value = props.item.reqPop || 0;
      reqJob.value = props.item.reqJob || 0;
      return;
    }

    // 检查缓存
    if (equipCache.has(props.item.itemId)) {
      const equipData = equipCache.get(props.item.itemId);
      reqLevel.value = equipData.reqLevel || 0;
      reqStr.value = equipData.reqSTR || 0;
      reqDex.value = equipData.reqDEX || 0;
      reqInt.value = equipData.reqINT || 0;
      reqLuk.value = equipData.reqLUK || 0;
      reqPop.value = equipData.reqPOP || 0;
      reqJob.value = equipData.reqJob || 0;
      return;
    }

    // 否则尝试异步获取 (兜底逻辑)
    try {
      const { data } = await getEquInitialInfo(props.item.itemId);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const equipData = data as any;
      if (equipData) {
        // 存入缓存
        equipCache.set(props.item.itemId, equipData);

        reqLevel.value = equipData.reqLevel || 0;
        reqStr.value = equipData.reqSTR || 0;
        reqDex.value = equipData.reqDEX || 0;
        reqInt.value = equipData.reqINT || 0;
        reqLuk.value = equipData.reqLUK || 0;
        reqPop.value = equipData.reqPOP || 0;
        reqJob.value = equipData.reqJob || 0;
      }
    } catch (e) {
      // ignore
    }
  };

  const fetchItemDesc = async () => {
    // 如果 props 中已经有描述，直接使用
    if (props.item.desc) {
      itemDesc.value = props.item.desc;
      return;
    }

    // 检查缓存
    if (equipDescCache.has(props.item.itemId)) {
      itemDesc.value = equipDescCache.get(props.item.itemId) || '';
      return;
    }

    // 否则尝试异步获取
    try {
      const { data } = await informationSearch({
        types: ['eqp'],
        filter: props.item.itemId.toString(),
        page: 1,
        pageSize: 1,
        fullMatch: true,
      });
      if (data && data.records && data.records.length > 0) {
        const record = data.records[0];
        if (record.desc) {
          equipDescCache.set(props.item.itemId, record.desc);
          itemDesc.value = record.desc;
        } else {
          // 如果没有描述，也缓存空字符串，避免重复请求
          equipDescCache.set(props.item.itemId, '');
          itemDesc.value = '';
        }
      } else {
        // 如果没有找到记录，也缓存空字符串
        equipDescCache.set(props.item.itemId, '');
        itemDesc.value = '';
      }
    } catch (e) {
      // ignore
    }
  };

  // 职业判断逻辑
  const canWearJob = (jobFlag: number) => {
    if (reqJob.value === 0 || reqJob.value === -1) return true; // 0 通常代表全职业
    if (jobFlag === 0) return false; // Beginner check (usually excluded if reqJob > 0)
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

  watch(
    () => props.item,
    () => {
      fetchInitialInfo();
      fetchItemDesc();
    },
    { immediate: true, deep: true }
  );
</script>

<script lang="ts">
  // 模块级缓存，所有组件实例共享
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const equipCache = new Map<number, any>();
  const equipDescCache = new Map<number, string>();
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
    padding: 10px;
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
