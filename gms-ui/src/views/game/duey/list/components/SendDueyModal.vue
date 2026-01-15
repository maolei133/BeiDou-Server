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
        <a-input
          v-model="form.senderName"
          :placeholder="$t('duey.send.sender.placeholder')"
        />
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
          <a-input-search
            v-model="form.itemId"
            :placeholder="$t('duey.send.itemId')"
            search-button
            style="flex: 1"
            @search="openItemSelector"
            @blur="handleIdBlur"
          >
            <template #button-icon>
              <icon-search />
            </template>
          </a-input-search>
          <a-input-number
            v-model="form.quantity"
            :placeholder="$t('duey.send.quantity')"
            :min="1"
            :max="32767"
            style="width: 100px; margin-left: 8px"
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
  import { ref, reactive, watch, computed } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import { sendDueyPackage, SendDueyReq } from '@/api/duey';
  import {
    getEquInitialInfo,
    getItemInitialInfo,
    getPlayerList,
    GiveForm,
  } from '@/api/player';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import ItemSelector from '@/components/ItemSelector/index.vue';
  import PlayerSelector from '@/components/PlayerSelector/index.vue';
  import GiveItemModal from '@/views/account/player/components/GiveItemModal.vue';
  import { IconSearch, IconUser, IconEdit } from '@arco-design/web-vue/es/icon';

  const props = defineProps<{
    visible: boolean;
    defaultReceiver?: string;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const { t } = useI18n();

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
    int: undefined,
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

  const rules = {
    // receiverIds: [{ required: true, message: t('duey.send.receiver.placeholder') }],
  };

  // 用于传递给 GiveItemModal 的数据
  const equipFormData = ref<GiveForm>({
    type: 6,
    expireType: 0,
  });

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
    form.int = undefined;
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

          // 填充默认属性
          form.str = equipData.str;
          form.dex = equipData.dex;
          form.int = equipData.int;
          form.luk = equipData.luk;
          form.hp = equipData.hp;
          form.mp = equipData.mp;
          form.watk = equipData.pad; // pad = watk
          form.matk = equipData.mad; // mad = matk
          form.wdef = equipData.pdd; // pdd = wdef
          form.mdef = equipData.mdd; // mdd = mdef
          form.acc = equipData.acc;
          form.avoid = equipData.eva; // eva = avoid
          form.hands = equipData.hands;
          form.speed = equipData.speed;
          form.jump = equipData.jump;
          form.upgradeSlots = equipData.tuc; // tuc = upgradeSlots

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

      Message.warning('未找到该物品信息');
    } catch (error) {
      // ignore
    }
  };

  const openItemSelector = () => {
    itemSelectorVisible.value = true;
  };

  const openPlayerSelector = () => {
    playerSelectorVisible.value = true;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleItemSelect = (item: any) => {
    form.itemId = item.id;
    handleIdBlur();
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

  const openEquipEditor = () => {
    if (!isEquip.value) return;

    // 将当前 form 的属性映射到 equipFormData
    equipFormData.value = {
      type: 6,
      id: form.itemId,
      str: form.str,
      dex: form.dex,
      int: form.int,
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
      expireType: 0, // 默认永久，或者根据需要传递
    };
    equipEditorVisible.value = true;
  };

  const handleEquipEditorSubmit = (data: GiveForm) => {
    // 将编辑后的属性回填到 form
    form.str = data.str;
    form.dex = data.dex;
    form.int = data.int;
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

    equipEditorVisible.value = false;
    Message.success('装备属性已更新');
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
      Message.success(t('duey.send.success'));
      emit('success');
      done(true);
    } catch (err) {
      done(false);
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
</style>
