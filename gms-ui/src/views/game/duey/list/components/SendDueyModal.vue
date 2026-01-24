<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="$t('duey.send.title')"
    width="400px"
    @cancel="handleCancel"
    @before-ok="handleBeforeOk"
  >
    <a-form
      ref="formRef"
      :model="form"
      :rules="rules"
      :label-col-props="{ span: 6 }"
      :wrapper-col-props="{ span: 18 }"
    >
      <!-- 第一行：收件人 和 配送类型 -->
      <a-row :gutter="16">
        <a-col :span="24">
          <a-form-item
            field="receiverIds"
            :label="$t('duey.send.receiver')"
            :rules="[
              {
                required: !form.isAll,
                message: $t('duey.send.receiver.placeholder'),
              },
            ]"
          >
            <div style="display: flex; align-items: center; width: 100%">
              <a-input-group style="flex: 1">
                <a-select
                  v-model="form.receiverIds"
                  :loading="loadingPlayers"
                  :placeholder="$t('duey.send.receiver.placeholder')"
                  multiple
                  allow-search
                  :max-tag-count="1"
                  style="flex: 1"
                  @search="handleSearchPlayers"
                  @dropdown-visible-change="handleDropdownVisibleChange"
                >
                  <template #header>
                    <div style="padding: 6px 12px">
                      <a-checkbox v-model="form.isAll">{{
                        $t('duey.send.isAll')
                      }}</a-checkbox>
                    </div>
                    <a-divider style="margin: 0" />
                  </template>
                  <a-option
                    v-for="player in playerOptions"
                    :key="player.id"
                    :value="player.id"
                    :disabled="form.isAll"
                  >
                    {{ player.name }}
                  </a-option>
                </a-select>
                <a-button @click="openPlayerSelector">
                  <template #icon>
                    <icon-user />
                  </template>
                </a-button>
              </a-input-group>
              <a-divider
                direction="vertical"
                style="height: 32px; margin: 0 8px"
              />
              <a-switch v-model="form.quick" style="flex-shrink: 0">
                <template #checked>{{ $t('duey.list.type.quick') }}</template>
                <template #unchecked>{{
                  $t('duey.list.type.normal')
                }}</template>
              </a-switch>
            </div>
          </a-form-item>
        </a-col>
      </a-row>

      <a-form-item field="senderName" :label="$t('duey.send.sender')">
        <a-select
          v-model="form.senderName"
          :placeholder="$t('duey.send.sender.placeholder')"
          allow-create
          allow-clear
        >
          <a-option
            v-for="name in senderHistory"
            :key="name"
            :value="name"
            class="sender-option"
          >
            <div class="sender-option-content">
              <span>{{ name }}</span>
              <icon-close
                class="delete-icon"
                @click.stop="removeSenderHistory(name)"
              />
            </div>
          </a-option>
        </a-select>
      </a-form-item>

      <a-form-item :label="$t('duey.send.expire')">
        <a-input-group style="width: 100%">
          <a-select v-model="expireType" style="width: 100px">
            <a-option value="days">{{ $t('duey.send.expire.days') }}</a-option>
            <a-option value="date">{{ $t('duey.send.expire.date') }}</a-option>
          </a-select>
          <a-input-number
            v-if="expireType === 'days'"
            v-model="form.expireDays"
            :placeholder="$t('duey.send.expire.days')"
            :min="1"
            style="flex: 1"
          />
          <a-date-picker
            v-else
            v-model="expireDateStr"
            show-time
            format="YYYY-MM-DD HH:mm:ss"
            style="flex: 1"
            @change="handleDateChange"
          />
        </a-input-group>
      </a-form-item>

      <a-form-item v-if="!form.quick" :label="$t('duey.send.deliveryTime')">
        <a-date-picker
          v-model="deliveryDateStr"
          show-time
          format="YYYY-MM-DD HH:mm:ss"
          style="width: 100%"
          @change="handleDeliveryDateChange"
        />
      </a-form-item>

      <a-form-item field="mesos" :label="$t('duey.send.mesos')">
        <a-input-number
          v-model="form.mesos"
          :placeholder="$t('duey.send.mesos')"
          :min="0"
          :max="2147483647"
        />
      </a-form-item>

      <!-- 物品选择和数量并列 -->
      <a-form-item field="itemId" :label="$t('duey.send.itemId')">
        <a-input-group style="width: 100%">
          <a-select
            v-model="form.itemId"
            :placeholder="$t('duey.send.itemId')"
            allow-search
            allow-create
            :loading="loadingItems"
            style="flex: 1"
            @search="handleSearchItems"
            @change="handleItemChange"
            @popup-visible-change="handleItemPopupVisibleChange"
          >
            <a-option
              v-for="item in itemOptions"
              :key="item.id"
              :value="item.id"
            >
              {{ item.name }} ({{ item.id }})
            </a-option>
          </a-select>
          <a-button @click="openItemSelector">
            <template #icon>
              <icon-search />
            </template>
          </a-button>
          <a-input-number
            v-model="form.quantity"
            :placeholder="$t('duey.send.quantity')"
            :min="1"
            :max="32767"
            hide-button
            style="width: 70px; margin-left: 8px"
          />
        </a-input-group>
      </a-form-item>

      <!-- 物品信息展示 -->
      <a-row v-if="itemInfo.name" style="margin-bottom: 20px">
        <a-col :span="18" :offset="6">
          <div class="item-info-container">
            <div class="item-icon-wrapper">
              <img :src="itemIconUrl" alt="Item Icon" class="item-icon" />
            </div>
            <div class="item-details">
              <a-input v-model="itemInfo.name" readonly> </a-input>
              <a-textarea
                v-model="itemInfo.desc"
                readonly
                auto-size
                style="margin-top: 8px"
              />
            </div>
            <div v-if="isEquip" class="item-actions">
              <a-button type="primary" size="small" @click="openEquipEditor">
                <template #icon>
                  <icon-edit />
                </template>
              </a-button>
            </div>
          </div>
        </a-col>
      </a-row>

      <a-form-item field="message" :label="$t('duey.send.message')">
        <a-textarea
          v-model="form.message"
          :placeholder="$t('duey.send.message')"
          :max-length="100"
          show-word-limit
        />
      </a-form-item>
    </a-form>

    <ItemSelector
      v-model:visible="itemSelectorVisible"
      :initial-id="form.itemId"
      @select="handleItemSelect"
    />

    <PlayerSelector
      v-model:visible="playerSelectorVisible"
      multiple
      @select="handlePlayerSelect"
    />

    <GiveItemModal
      v-model:visible="equipEditorVisible"
      :title="$t('duey.send.equipStats')"
      :initial-data="equipFormData"
      :is-edit-mode="true"
      @submit="handleEquipEditorSubmit"
    />
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, watch, computed, onMounted } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import dayjs from 'dayjs';
  import { sendDueyPackage, SendDueyReq } from '@/api/duey';
  import {
    getEquInitialInfo,
    getItemInitialInfo,
    getPlayerList,
    GiveForm,
  } from '@/api/player';
  import { informationSearch } from '@/api/information';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import ItemSelector from '@/components/ItemSelector/index.vue';
  import PlayerSelector from '@/components/PlayerSelector/index.vue';
  import GiveItemModal from '@/views/account/player/components/GiveItemModal.vue';
  import {
    IconSearch,
    IconUser,
    IconEdit,
    IconClose,
  } from '@arco-design/web-vue/es/icon';

  const props = defineProps<{
    visible: boolean;
    defaultReceiver?: string;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const { t } = useI18n();
  const { setLoading } = useLoading(false);

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const formRef = ref();
  const form = reactive<SendDueyReq>({
    isAll: false,
    receiverIds: [],
    mesos: 0,
    itemId: undefined,
    quantity: 1,
    message: '',
    quick: true,
    senderName: '',
    expireDays: 30,
    expireTime: undefined,
    deliveryTime: undefined,
    // 装备属性
    str: undefined,
    dex: undefined,
    inte: undefined, // 统一为 inte
    luk: undefined,
    hp: undefined,
    mp: undefined,
    watk: undefined,
    matk: undefined,
    wdef: undefined,
    mdef: undefined,
    acc: undefined,
    avoid: undefined,
    hands: undefined,
    speed: undefined,
    jump: undefined,
    upgradeSlots: undefined,
    level: undefined,
    itemLevel: undefined,
    flag: undefined,
    vicious: undefined,
    owner: undefined,
    itemExpiration: undefined,
  });

  const expireType = ref('days');
  const expireDateStr = ref<string | undefined>(undefined);
  const deliveryDateStr = ref<string | undefined>(undefined);
  const itemSelectorVisible = ref(false);
  const playerSelectorVisible = ref(false);
  const equipEditorVisible = ref(false);

  const itemInfo = reactive({
    name: '',
    desc: '',
  });
  const itemIconUrl = ref('');
  const lastFetchedId = ref<number | undefined>(undefined);
  const isEquip = ref(false);

  const loadingPlayers = ref(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const playerOptions = ref<any[]>([]);

  const senderHistory = ref<string[]>([]);

  const loadingItems = ref(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const itemOptions = ref<any[]>([]);

  const rules = {
    // receiverIds: [{ required: true, message: t('duey.send.receiver.placeholder') }],
  };

  // 用于传递给 GiveItemModal 的数据
  const equipFormData = ref<GiveForm>({
    type: 6,
    expireType: 0,
  });

  const loadSenderHistory = () => {
    const history = localStorage.getItem('duey_sender_history');
    if (history) {
      try {
        senderHistory.value = JSON.parse(history);
      } catch (e) {
        senderHistory.value = [];
      }
    }
  };

  const saveSenderHistory = (name: string) => {
    if (!name) return;
    let history = [...senderHistory.value];
    // Remove if exists to move to top
    history = history.filter((n) => n !== name);
    history.unshift(name);
    // Keep only last 10
    if (history.length > 10) {
      history = history.slice(0, 10);
    }
    senderHistory.value = history;
    localStorage.setItem('duey_sender_history', JSON.stringify(history));
  };

  const removeSenderHistory = (name: string) => {
    senderHistory.value = senderHistory.value.filter((n) => n !== name);
    localStorage.setItem(
      'duey_sender_history',
      JSON.stringify(senderHistory.value)
    );
  };

  const handleSearchPlayers = async (value: string) => {
    loadingPlayers.value = true;
    try {
      const { data } = await getPlayerList({
        pageNo: 1,
        pageSize: 20,
        name: value,
        status: 0, // All
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      playerOptions.value = (data as any).records;

      // 如果有默认收件人，确保他在列表中
      if (props.defaultReceiver && value === props.defaultReceiver) {
        const found = playerOptions.value.find(
          (p) => p.name === props.defaultReceiver
        );
        if (found) {
          form.receiverIds = [found.id];
        }
      }
    } finally {
      loadingPlayers.value = false;
    }
  };

  const resetEquipStats = () => {
    form.str = undefined;
    form.dex = undefined;
    form.inte = undefined;
    form.luk = undefined;
    form.hp = undefined;
    form.mp = undefined;
    form.watk = undefined;
    form.matk = undefined;
    form.wdef = undefined;
    form.mdef = undefined;
    form.acc = undefined;
    form.avoid = undefined;
    form.hands = undefined;
    form.speed = undefined;
    form.jump = undefined;
    form.upgradeSlots = undefined;
    form.level = undefined;
    form.itemLevel = undefined;
    form.flag = undefined;
    form.vicious = undefined;
    form.owner = undefined;
    form.itemExpiration = undefined;
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        // Reset form
        formRef.value?.resetFields();
        form.isAll = false;
        form.receiverIds = [];
        form.mesos = 0;
        form.itemId = undefined;
        form.quantity = 1;
        form.message = '';
        form.quick = true;
        form.senderName = '';
        form.expireDays = 30;
        form.expireTime = undefined;
        form.deliveryTime = undefined;
        // Reset equip stats
        resetEquipStats();

        expireType.value = 'days';
        expireDateStr.value = undefined;
        deliveryDateStr.value = undefined;
        itemInfo.name = '';
        itemInfo.desc = '';
        itemIconUrl.value = '';
        lastFetchedId.value = undefined;
        isEquip.value = false;

        loadSenderHistory();
        itemOptions.value = [];

        if (props.defaultReceiver) {
          // 如果有默认收件人，尝试搜索并选中
          handleSearchPlayers(props.defaultReceiver);
        }
      }
    }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleDateChange = (dateString: string | undefined) => {
    if (dateString) {
      form.expireTime = new Date(dateString).getTime();
      form.expireDays = undefined;
    } else {
      form.expireTime = undefined;
    }
  };

  const handleDeliveryDateChange = (dateString: string | undefined) => {
    if (dateString) {
      form.deliveryTime = new Date(dateString).getTime();
    } else {
      form.deliveryTime = undefined;
    }
  };

  watch(expireType, (val) => {
    if (val === 'days') {
      form.expireTime = undefined;
      expireDateStr.value = undefined;
      form.expireDays = 30;
    } else {
      form.expireDays = undefined;
    }
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getAttr = (data: any, keys: string[]) => {
    // eslint-disable-next-line no-restricted-syntax
    for (const key of keys) {
      if (data[key] !== undefined && data[key] !== null) return data[key];
    }
    return 0;
  };

  const handleIdBlur = async () => {
    if (!form.itemId) {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';
      lastFetchedId.value = undefined;
      isEquip.value = false;
      return;
    }

    if (form.itemId === lastFetchedId.value) {
      return;
    }
    lastFetchedId.value = form.itemId;

    setLoading(true);
    try {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';
      isEquip.value = false;

      // 尝试作为装备查询
      try {
        const { data } = await getEquInitialInfo(form.itemId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;
        if (equipData) {
          itemInfo.name = equipData.name;
          itemInfo.desc = equipData.desc;
          itemIconUrl.value = getIconUrl('item', form.itemId);
          isEquip.value = true;

          // 填充默认属性，尝试多种字段名以兼容不同后端返回格式
          form.str = getAttr(equipData, ['str', 'Str']);
          form.dex = getAttr(equipData, ['dex', 'Dex']);
          form.inte = getAttr(equipData, ['int', 'Int', 'intel', 'Intel']);
          form.luk = getAttr(equipData, ['luk', 'Luk']);
          form.hp = getAttr(equipData, ['hp', 'Hp', 'HP']);
          form.mp = getAttr(equipData, ['mp', 'Mp', 'MP']);
          form.watk = getAttr(equipData, ['pAtk', 'pad', 'watk', 'Watk']);
          form.matk = getAttr(equipData, ['mAtk', 'mad', 'matk', 'Matk']);
          form.wdef = getAttr(equipData, ['pDef', 'pdd', 'wdef', 'Wdef']);
          form.mdef = getAttr(equipData, ['mDef', 'mdd', 'mdef', 'Mdef']);
          form.acc = getAttr(equipData, ['acc', 'Acc']);
          form.avoid = getAttr(equipData, ['avoid', 'eva', 'Avoid']);
          form.hands = getAttr(equipData, ['hands', 'Hands']);
          form.speed = getAttr(equipData, ['speed', 'Speed']);
          form.jump = getAttr(equipData, ['jump', 'Jump']);
          form.upgradeSlots = getAttr(equipData, [
            'upgradeSlot',
            'tuc',
            'upgradeSlots',
          ]);
          form.level = getAttr(equipData, ['level', 'Level']);
          form.itemLevel = getAttr(equipData, ['itemLevel', 'ItemLevel']) || 1;
          form.vicious = getAttr(equipData, ['vicious', 'Vicious']);
          form.flag = getAttr(equipData, ['flag', 'Flag']);

          Message.success(t('account.player.equip.success'));
          return;
        }
      } catch (e) {
        // ignore
      }

      // 尝试作为道具查询
      try {
        const { data } = await getItemInitialInfo(form.itemId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const itemData = data as any;
        if (itemData) {
          itemInfo.name = itemData.name;
          itemInfo.desc = itemData.desc;
          itemIconUrl.value = getIconUrl('item', form.itemId);
          return;
        }
      } catch (e) {
        // ignore
      }

      Message.warning(t('duey.send.item.notFound'));
      // 如果未找到物品信息，重置相关状态
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';
      isEquip.value = false;
    } catch (error) {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  const openItemSelector = () => {
    itemSelectorVisible.value = true;
  };

  const openPlayerSelector = () => {
    playerSelectorVisible.value = true;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleItemSelect = async (item: any) => {
    form.itemId = item.id;
    // 强制触发 handleIdBlur 的查询逻辑，确保获取完整属性
    lastFetchedId.value = undefined;
    await handleIdBlur();
    itemSelectorVisible.value = false;
  };

  const handleDropdownVisibleChange = (visible: boolean) => {
    if (visible) {
      // 如果没有选项，加载一些默认的
      if (playerOptions.value.length === 0) {
        handleSearchPlayers('');
      }
    }
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handlePlayerSelect = (players: any[]) => {
    // players is array of OnlinePlayer
    const ids = players.map((p) => p.id);
    // Merge with existing ids, avoid duplicates
    const newIds = [...new Set([...(form.receiverIds || []), ...ids])];
    form.receiverIds = newIds;

    // Update options to ensure selected players are visible
    players.forEach((p) => {
      if (!playerOptions.value.find((opt) => opt.id === p.id)) {
        playerOptions.value.push(p);
      }
    });
  };

  const bitmaskToArray = (mask: number | undefined): number[] => {
    if (!mask) return [];
    const flags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x80, 0x100, 0x200];
    return flags.filter((f) => (mask & f) === f);
  };

  const openEquipEditor = () => {
    if (!isEquip.value) return;

    // 将当前 form 的属性映射到 equipFormData
    equipFormData.value = {
      type: 6,
      id: form.itemId,
      str: form.str,
      dex: form.dex,
      int: form.inte,
      luk: form.luk,
      hp: form.hp,
      mp: form.mp,
      pAtk: form.watk,
      mAtk: form.matk,
      pDef: form.wdef,
      mDef: form.mdef,
      acc: form.acc,
      avoid: form.avoid,
      hands: form.hands,
      speed: form.speed,
      jump: form.jump,
      upgradeSlot: form.upgradeSlots,
      level: form.level,
      itemLevel: form.itemLevel,
      flag: bitmaskToArray(form.flag),
      vicious: form.vicious,
      owner: form.owner,
      expire: form.itemExpiration,
      expireType: form.itemExpiration ? 2 : 0, // 默认永久，或者根据需要传递
      expireDate: form.itemExpiration
        ? dayjs(form.itemExpiration).format('YYYY-MM-DD HH:mm:ss')
        : undefined,
    };
    equipEditorVisible.value = true;
  };

  const handleEquipEditorSubmit = (data: GiveForm) => {
    // 将编辑后的属性回填到 form
    form.str = data.str;
    form.dex = data.dex;
    form.inte = data.int;
    form.luk = data.luk;
    form.hp = data.hp;
    form.mp = data.mp;
    form.watk = data.pAtk;
    form.matk = data.mAtk;
    form.wdef = data.pDef;
    form.mdef = data.mDef;
    form.acc = data.acc;
    form.avoid = data.avoid;
    form.hands = data.hands;
    form.speed = data.speed;
    form.jump = data.jump;
    form.upgradeSlots = data.upgradeSlot;
    form.level = data.level;
    form.itemLevel = data.itemLevel;
    form.flag = Array.isArray(data.flag)
      ? data.flag.reduce((acc, cur) => acc | cur, 0)
      : data.flag;
    form.vicious = data.vicious;
    form.owner = data.owner;

    // 处理过期时间
    if (data.expireType === 0) {
      form.itemExpiration = undefined;
    } else if (data.expireType === 1 && data.expire) {
      // 分钟
      form.itemExpiration = new Date().getTime() + data.expire * 60 * 1000;
    } else if (data.expireType === 2 && data.expireDate) {
      // 日期
      form.itemExpiration = new Date(data.expireDate).getTime();
    }

    equipEditorVisible.value = false;
    Message.success(t('duey.send.equip.updateSuccess'));
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleBeforeOk = async (done: any) => {
    const res = await formRef.value?.validate();
    if (res) {
      done(false);
      return;
    }

    if (!form.isAll && (!form.receiverIds || form.receiverIds.length === 0)) {
      Message.error(t('duey.send.receiver.placeholder'));
      done(false);
      return;
    }

    try {
      await sendDueyPackage(form);
      saveSenderHistory(form.senderName || '');
      Message.success(t('duey.send.success'));
      emit('success');
      done(true);
    } catch (err) {
      done(false);
    }
  };

  onMounted(() => {
    loadSenderHistory();
  });

  const handleSearchItems = async (value: string) => {
    // 如果输入的是数字，且长度较短，可能是ID，也可能是名字的一部分
    // 但如果用户输入非数字，肯定是搜索名字
    // 这里我们简单处理：只要输入了内容，就去搜索
    if (!value) {
      itemOptions.value = [];
      return;
    }

    // 如果是纯数字，且我们想优先当做ID处理，可以在这里判断
    // 但需求是“输入内容非ID，则转为搜索”，这意味着如果输入的是数字，可能还是优先当ID？
    // 或者说，输入框本身是 allow-create，用户输入数字回车，v-model 会变成该数字
    // 这里的 handleSearchItems 是在用户输入过程中触发的搜索建议

    loadingItems.value = true;
    try {
      const { data } = await informationSearch({
        filter: value,
        page: 1,
        pageSize: 20,
        types: ['eqp', 'consume', 'ins', 'etc', 'cash'], // 搜索所有类型
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const records = (data as any).records || [];
      itemOptions.value = records;

      // 如果只找到1条记录，且用户输入的内容不是纯数字ID（或者即便是纯数字，但完全匹配了名字？）
      // 需求说：如果只找到1条记录，则转为ID填充到输入框里并执行后续的功能
      // 这里是在搜索回调中，直接修改 form.itemId 可能会打断用户输入
      // 通常这种“自动填充”是在用户停止输入（blur）或者回车时触发比较好
      // 但既然需求如此，我们可以尝试在搜索结果返回时判断
      if (records.length === 1) {
        // 只有当用户输入的内容不是该物品的ID时，才自动替换？
        // 或者直接替换
        // 为了避免用户正在输入时突然变了，我们可能需要谨慎一点
        // 但根据需求描述，似乎是希望自动完成
        // 这里我们先只做展示，真正的“转为ID填充”逻辑放在 handleItemChange 或 blur 中可能更好
        // 不过，如果是 allow-create 的 select，选中 option 会触发 change
        // 如果我们在这里直接改 form.itemId，用户体验可能会比较怪（输入一半突然变了）
        // 让我们在 handleItemPopupVisibleChange 或 blur 中处理“只找到1条”的逻辑？
        // 或者，需求的意思是：用户输入 -> 搜索 -> 只有1条 -> 自动选中
        // 这在 UI 上表现为：下拉框只有一个选项，用户可以直接回车选中，或者我们帮他选中
      }
    } finally {
      loadingItems.value = false;
    }
  };

  const handleItemChange = (value: any) => {
    // 当用户选中下拉项，或者输入自定义值回车后触发
    // value 可能是 ID (number) 或 输入的字符串 (string)
    if (typeof value === 'string') {
      // 用户输入了字符串（非ID，或者ID但没选中下拉项）
      // 尝试解析为数字
      const id = Number(value);
      if (!Number.isNaN(id)) {
        form.itemId = id;
      } else if (itemOptions.value.length === 1) {
        // 输入的不是数字，可能是名字，且没有选中下拉项（或者下拉项里没有）
        // 此时 itemOptions 可能已经加载了搜索结果
        form.itemId = itemOptions.value[0].id;
        Message.info(
          t('duey.send.item.autoMatched', { name: itemOptions.value[0].name })
        );
      } else if (itemOptions.value.length > 1) {
        // 多条结果，提示用户选择
        // form.itemId 此时是字符串，可能会导致后续逻辑报错，需要清空或保持
        // 但由于 allow-create，v-model 绑定的值可以是 string
        // 我们需要确保最终提交或查询详情时是 ID
        // 这里可以不做处理，等待 blur 时校验
      } else {
        // 没有结果
      }
    } else {
      form.itemId = value;
    }
    // 触发详情查询
    if (typeof form.itemId === 'number') {
      lastFetchedId.value = undefined;
      handleIdBlur();
    }
  };

  const handleItemPopupVisibleChange = (visible: boolean) => {
    if (!visible) {
      // 下拉框关闭时，检查当前值
      // 如果 itemOptions 只有1条，且当前 form.itemId 不是数字，可以尝试自动填充
      if (
        itemOptions.value.length === 1 &&
        typeof form.itemId !== 'number' &&
        form.itemId
      ) {
        form.itemId = itemOptions.value[0].id;
        lastFetchedId.value = undefined;
        handleIdBlur();
      }
    }
  };
</script>

<style scoped>
  .item-info-container {
    display: flex;
    border: 1px solid var(--color-neutral-3);
    padding: 10px;
    border-radius: 4px;
    position: relative;
  }
  .item-icon-wrapper {
    margin-right: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 60px;
  }
  .item-icon {
    max-width: 100%;
    max-height: 100%;
  }
  .item-details {
    flex: 1;
    margin-right: 40px; /* 留出按钮空间 */
  }
  .item-actions {
    position: absolute;
    right: 10px;
    top: 10px;
  }
  .sender-option-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
  }
  .delete-icon {
    color: var(--color-text-3);
    cursor: pointer;
    font-size: 12px;
    padding: 4px;
  }
  .delete-icon:hover {
    color: rgb(var(--danger-6));
    background-color: var(--color-fill-2);
    border-radius: 50%;
  }
</style>
