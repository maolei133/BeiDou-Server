<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="$t('duey.send.title')"
    width="600px"
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

      <!-- 物品列表 -->
      <a-form-item :label="$t('duey.send.items')">
        <div style="width: 100%">
          <a-button type="outline" size="small" @click="addItem">
            <template #icon>
              <icon-plus />
            </template>
            {{ $t('duey.send.addItem') }}
          </a-button>

          <div
            v-for="(item, index) in form.items"
            :key="index"
            class="item-row"
          >
            <div class="item-row-header">
              <span>{{ $t('duey.send.item') }} {{ index + 1 }}</span>
              <a-button
                type="text"
                status="danger"
                size="mini"
                @click="removeItem(index)"
              >
                <template #icon>
                  <icon-delete />
                </template>
              </a-button>
            </div>
            <a-input-group style="width: 100%">
              <a-select
                v-model="item.itemId"
                :placeholder="$t('duey.send.itemId')"
                allow-search
                allow-create
                allow-clear
                :loading="loadingItems"
                style="flex: 1"
                @search="handleSearchItems"
                @change="(val) => handleItemChange(val, index)"
                @clear="() => handleItemClear(index)"
                @popup-visible-change="
                  (visible) => handleItemPopupVisibleChange(visible, index)
                "
              >
                <a-option
                  v-for="opt in itemOptions"
                  :key="opt.id"
                  :value="opt.id"
                >
                  {{ opt.name }} ({{ opt.id }})
                </a-option>
              </a-select>
              <a-button @click="openItemSelector(index)">
                <template #icon>
                  <icon-search />
                </template>
              </a-button>
              <a-input-number
                v-model="item.quantity"
                :placeholder="$t('duey.send.quantity')"
                :min="1"
                :max="32767"
                hide-button
                style="width: 100px; margin-left: 8px"
              />
            </a-input-group>

            <!-- 物品信息展示 -->
            <div v-if="item.name" class="item-info-container">
              <div class="item-icon-wrapper">
                <img
                  :src="getIconUrl('item', item.itemId)"
                  alt="Item Icon"
                  class="item-icon"
                />
              </div>
              <div class="item-details">
                <div class="item-name">{{ item.name }}</div>
                <div v-if="isEquipItem(item.itemId)" class="item-actions">
                  <a-button
                    type="primary"
                    size="mini"
                    @click="openEquipEditor(index)"
                  >
                    <template #icon>
                      <icon-edit />
                    </template>
                    {{ $t('duey.send.editStats') }}
                  </a-button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </a-form-item>

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
      :initial-id="currentItemId"
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
  import { sendDueyPackage, SendDueyReq, DueyPackage } from '@/api/duey';
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
    IconPlus,
    IconDelete,
  } from '@arco-design/web-vue/es/icon';

  const props = defineProps<{
    visible: boolean;
    defaultReceiver?: string;
    initialData?: DueyPackage; // 新增：传入初始数据用于编辑
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
    packageId: undefined, // 新增：用于更新
    isAll: false,
    receiverIds: [],
    mesos: 0,
    message: '',
    quick: true,
    senderName: '',
    expireDays: 30,
    expireTime: undefined,
    deliveryTime: undefined,
    items: [], // 物品列表
  });

  const expireType = ref('days');
  const expireDateStr = ref<string | undefined>(undefined);
  const deliveryDateStr = ref<string | undefined>(undefined);
  const itemSelectorVisible = ref(false);
  const playerSelectorVisible = ref(false);
  const equipEditorVisible = ref(false);
  const currentItemIndex = ref<number>(-1);
  const currentItemId = ref<number | undefined>(undefined);

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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getAttr = (data: any, keys: string[]) => {
    // eslint-disable-next-line no-restricted-syntax
    for (const key of keys) {
      if (data[key] !== undefined && data[key] !== null) return data[key];
    }
    return 0;
  };

  const fetchItemInfo = async (itemId: number) => {
    try {
      // 尝试作为装备查询
      try {
        const { data } = await getEquInitialInfo(itemId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;
        if (equipData) {
          return {
            name: equipData.name,
            desc: equipData.desc,
            isEquip: true,
            data: equipData,
          };
        }
      } catch (e) {
        // ignore
      }

      // 尝试作为道具查询
      try {
        const { data } = await getItemInitialInfo(itemId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const itemData = data as any;
        if (itemData) {
          return {
            name: itemData.name,
            desc: itemData.desc,
            isEquip: false,
            data: itemData,
          };
        }
      } catch (e) {
        // ignore
      }
    } catch (error) {
      // ignore
    }
    return null;
  };

  const handleIdBlur = async (index: number) => {
    if (!form.items || !form.items[index]) return;
    const item = form.items[index];
    if (!item.itemId) {
      item.name = undefined;
      return;
    }

    setLoading(true);
    try {
      const info = await fetchItemInfo(item.itemId);
      if (info) {
        item.name = info.name;
        if (info.isEquip) {
          // 填充默认属性
          const equipData = info.data;
          item.str = getAttr(equipData, ['str', 'Str']);
          item.dex = getAttr(equipData, ['dex', 'Dex']);
          item.int = getAttr(equipData, ['int', 'Int', 'intel', 'Intel']);
          item.luk = getAttr(equipData, ['luk', 'Luk']);
          item.hp = getAttr(equipData, ['hp', 'Hp', 'HP']);
          item.mp = getAttr(equipData, ['mp', 'Mp', 'MP']);
          item.watk = getAttr(equipData, ['pAtk', 'pad', 'watk', 'Watk']);
          item.matk = getAttr(equipData, ['mAtk', 'mad', 'matk', 'Matk']);
          item.wdef = getAttr(equipData, ['pDef', 'pdd', 'wdef', 'Wdef']);
          item.mdef = getAttr(equipData, ['mDef', 'mdd', 'mdef', 'Mdef']);
          item.acc = getAttr(equipData, ['acc', 'Acc']);
          item.avoid = getAttr(equipData, ['avoid', 'eva', 'Avoid']);
          item.hands = getAttr(equipData, ['hands', 'Hands']);
          item.speed = getAttr(equipData, ['speed', 'Speed']);
          item.jump = getAttr(equipData, ['jump', 'Jump']);
          item.upgradeSlots = getAttr(equipData, [
            'upgradeSlot',
            'tuc',
            'upgradeSlots',
          ]);
          item.level = getAttr(equipData, ['level', 'Level']);
          item.itemLevel = getAttr(equipData, ['itemLevel', 'ItemLevel']) || 1;
          item.vicious = getAttr(equipData, ['vicious', 'Vicious']);
          item.flag = getAttr(equipData, ['flag', 'Flag']);
        }
      } else {
        Message.warning(t('duey.send.item.notFound'));
        item.name = undefined;
      }
    } finally {
      setLoading(false);
    }
  };

  const addItem = () => {
    if (!form.items) form.items = [];
    form.items.push({
      itemId: undefined as unknown as number, // 初始为空
      quantity: 1,
    });
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        // Reset form
        formRef.value?.resetFields();
        form.packageId = undefined; // 重置 packageId
        form.isAll = false;
        form.receiverIds = [];
        form.mesos = 0;
        form.message = '';
        form.quick = true;
        form.senderName = '';
        form.expireDays = 30;
        form.expireTime = undefined;
        form.deliveryTime = undefined;
        form.items = [];

        expireType.value = 'days';
        expireDateStr.value = undefined;
        deliveryDateStr.value = undefined;

        loadSenderHistory();
        itemOptions.value = [];

        if (props.defaultReceiver) {
          // 如果有默认收件人，尝试搜索并选中
          handleSearchPlayers(props.defaultReceiver);
        }

        // 如果传入了 initialData，进行回显
        if (props.initialData) {
          const data = props.initialData;
          form.packageId = data.packageId; // 设置 packageId
          form.receiverIds = [data.receiverId];
          // 预加载收件人信息以显示名字
          if (data.receiverName) {
            playerOptions.value = [
              { id: data.receiverId, name: data.receiverName },
            ];
          }

          form.senderName = data.senderName;
          form.mesos = data.mesos;
          form.message = data.message;
          form.quick = data.type === 1;

          // 处理物品
          if (data.items && data.items.length > 0) {
            form.items = data.items.map((item) => ({ ...item }));
          }

          // 处理过期时间
          if (data.expireTime) {
            expireType.value = 'date';
            expireDateStr.value = dayjs(data.expireTime).format(
              'YYYY-MM-DD HH:mm:ss'
            );
            form.expireTime = new Date(data.expireTime).getTime();
          }

          // 处理配送时间
          if (data.deliveryTime) {
            deliveryDateStr.value = dayjs(data.deliveryTime).format(
              'YYYY-MM-DD HH:mm:ss'
            );
            form.deliveryTime = new Date(data.deliveryTime).getTime();
          }
        } else {
          // 默认添加一个空物品行
          addItem();
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

  const removeItem = (index: number) => {
    if (form.items) {
      form.items.splice(index, 1);
    }
  };

  const openItemSelector = (index: number) => {
    currentItemIndex.value = index;
    if (form.items && form.items[index]) {
      currentItemId.value = form.items[index].itemId;
    } else {
      currentItemId.value = undefined;
    }
    itemSelectorVisible.value = true;
  };

  const openPlayerSelector = () => {
    playerSelectorVisible.value = true;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleItemSelect = async (item: any) => {
    if (currentItemIndex.value !== -1 && form.items) {
      const targetItem = form.items[currentItemIndex.value];
      targetItem.itemId = item.id;
      // 强制触发 handleIdBlur 的查询逻辑，确保获取完整属性
      await handleIdBlur(currentItemIndex.value);
    }
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
    form.receiverIds = [...new Set([...(form.receiverIds || []), ...ids])];

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

  const isEquipItem = (itemId: number) => {
    return Math.floor(itemId / 1000000) === 1;
  };

  const openEquipEditor = (index: number) => {
    if (!form.items || !form.items[index]) return;
    const item = form.items[index];
    if (!isEquipItem(item.itemId)) return;

    currentItemIndex.value = index;

    // 将当前 item 的属性映射到 equipFormData
    equipFormData.value = {
      type: 6,
      id: item.itemId,
      str: item.str,
      dex: item.dex,
      int: item.int,
      luk: item.luk,
      hp: item.hp,
      mp: item.mp,
      pAtk: item.watk,
      mAtk: item.matk,
      pDef: item.wdef,
      mDef: item.mdef,
      acc: item.acc,
      avoid: item.avoid,
      hands: item.hands,
      speed: item.speed,
      jump: item.jump,
      upgradeSlot: item.upgradeSlots,
      level: item.level,
      itemLevel: item.itemLevel,
      flag: bitmaskToArray(item.flag),
      vicious: item.vicious,
      owner: item.owner,
      expire: item.expiration,
      expireType: item.expiration ? 2 : 0, // 默认永久，或者根据需要传递
      expireDate: item.expiration
        ? dayjs(item.expiration).format('YYYY-MM-DD HH:mm:ss')
        : undefined,
    };
    equipEditorVisible.value = true;
  };

  const handleEquipEditorSubmit = (data: GiveForm) => {
    if (currentItemIndex.value === -1 || !form.items) return;
    const item = form.items[currentItemIndex.value];

    // 将编辑后的属性回填到 item
    item.str = data.str;
    item.dex = data.dex;
    item.int = data.int;
    item.luk = data.luk;
    item.hp = data.hp;
    item.mp = data.mp;
    item.watk = data.pAtk;
    item.matk = data.mAtk;
    item.wdef = data.pDef;
    item.mdef = data.mDef;
    item.acc = data.acc;
    item.avoid = data.avoid;
    item.hands = data.hands;
    item.speed = data.speed;
    item.jump = data.jump;
    item.upgradeSlots = data.upgradeSlot;
    item.level = data.level;
    item.itemLevel = data.itemLevel;
    item.flag = Array.isArray(data.flag)
      ? data.flag.reduce((acc, cur) => acc | cur, 0)
      : data.flag;
    item.vicious = data.vicious;
    item.owner = data.owner;

    // 处理过期时间
    if (data.expireType === 0) {
      item.expiration = undefined;
    } else if (data.expireType === 1 && data.expire) {
      // 分钟
      item.expiration = new Date().getTime() + data.expire * 60 * 1000;
    } else if (data.expireType === 2 && data.expireDate) {
      // 日期
      item.expiration = new Date(data.expireDate).getTime();
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

    // 过滤掉无效物品
    if (form.items) {
      form.items = form.items.filter((item) => item.itemId && item.itemId > 0);
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
    if (!value) {
      itemOptions.value = [];
      return;
    }

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
    } finally {
      loadingItems.value = false;
    }
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleItemChange = (value: any, index: number) => {
    if (!form.items || !form.items[index]) return;
    const item = form.items[index];

    if (typeof value === 'string') {
      const id = Number(value);
      if (!Number.isNaN(id)) {
        item.itemId = id;
      } else if (itemOptions.value.length === 1) {
        item.itemId = itemOptions.value[0].id;
        Message.info(
          t('duey.send.item.autoMatched', { name: itemOptions.value[0].name })
        );
      }
    } else {
      item.itemId = value;
    }
    // 触发详情查询
    if (typeof item.itemId === 'number') {
      handleIdBlur(index);
    }
  };

  const handleItemClear = (index: number) => {
    if (!form.items || !form.items[index]) return;
    const item = form.items[index];
    item.itemId = undefined as unknown as number;
    item.name = undefined;
  };

  const handleItemPopupVisibleChange = (visible: boolean, index: number) => {
    if (!visible && form.items && form.items[index]) {
      const item = form.items[index];
      if (
        itemOptions.value.length === 1 &&
        typeof item.itemId !== 'number' &&
        item.itemId
      ) {
        item.itemId = itemOptions.value[0].id;
        handleIdBlur(index);
      }
    }
  };
</script>

<style scoped>
  .item-row {
    border: 1px solid var(--color-neutral-3);
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 10px;
  }
  .item-row-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
    font-weight: bold;
    color: var(--color-text-2);
  }
  .item-info-container {
    display: flex;
    margin-top: 10px;
    background-color: var(--color-fill-2);
    padding: 8px;
    border-radius: 4px;
  }
  .item-icon-wrapper {
    margin-right: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    background-color: var(--color-bg-1);
    border-radius: 4px;
  }
  .item-icon {
    max-width: 100%;
    max-height: 100%;
  }
  .item-details {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  .item-name {
    font-weight: bold;
    margin-bottom: 4px;
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
