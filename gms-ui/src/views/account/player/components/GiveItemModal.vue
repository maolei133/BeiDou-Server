<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="title"
    :ok-loading="loading"
    :mask-closable="false"
    :esc-to-close="false"
    :ok-text="isEditMode ? $t('button.confirm') : $t('account.player.give')"
    width="500px"
    @before-ok="submitClick"
    @cancel="handleCancel"
  >
    <a-form :model="formData" class="form-aligned">
      <a-row :gutter="16">
        <a-col :span="24">
          <a-form-item
            v-if="!isEditMode && formData.playerId !== 0"
            field="player"
            :label="$t('account.player.form.player')"
          >
            <a-input v-model="formData.player" disabled style="width: 100%" />
          </a-form-item>
          <a-form-item
            v-if="!isEditMode"
            field="type"
            :label="$t('account.player.form.type')"
          >
            <a-select
              v-model="formData.type"
              style="width: 100%"
              @change="handleTypeChange"
            >
              <a-option :value="0">{{
                $t('account.player.nxCredit')
              }}</a-option>
              <a-option :value="1">{{
                $t('account.player.nxPrepaid')
              }}</a-option>
              <a-option :value="2">{{
                $t('account.player.maplePoint')
              }}</a-option>
              <a-option :value="3">{{ $t('account.player.mesos') }}</a-option>
              <a-option :value="4">{{ $t('account.player.exp') }}</a-option>
              <a-option :value="5">{{ $t('account.player.item') }}</a-option>
              <a-option :value="6">{{ $t('account.player.equip') }}</a-option>
              <a-option :value="7">{{ $t('account.player.expRate') }}</a-option>
              <a-option :value="8">{{
                $t('account.player.mesosRate')
              }}</a-option>
              <a-option :value="9">{{
                $t('account.player.dropRate')
              }}</a-option>
            </a-select>
          </a-form-item>
          <a-form-item
            v-if="formData.type === 5"
            field="id"
            :label="$t('account.player.form.id')"
          >
            <a-input-search
              v-model="formData.id"
              style="width: 100%"
              search-button
              @search="openItemSelector"
              @blur="handleIdBlur"
            >
              <template #button-icon>
                <icon-search />
              </template>
            </a-input-search>
          </a-form-item>
          <a-form-item
            v-if="
              formData.type === 0 ||
              formData.type === 1 ||
              formData.type === 2 ||
              formData.type === 3 ||
              formData.type === 4
            "
            field="quantity"
            :label="$t('account.player.form.quantity')"
          >
            <a-input-number v-model="formData.quantity" style="width: 100%" />
          </a-form-item>
          <a-form-item
            v-if="
              formData.type === 7 || formData.type === 8 || formData.type === 9
            "
            field="rate"
            :label="$t('account.player.form.rate')"
            :rules="[
              {
                required: true,
                message: $t('account.player.form.rate.required'),
              },
              {
                type: 'number',
                min: 0,
                message: $t('account.player.form.rate.type'),
              },
            ]"
          >
            <a-input-number v-model="formData.rate" style="width: 100%" />
          </a-form-item>
        </a-col>
      </a-row>
      <template v-if="formData.type === 6 || formData.type === 5">
        <a-row :gutter="16">
          <a-col v-if="formData.type === 6" :span="24">
            <a-form-item field="id" :label="$t('account.player.form.equipId')">
              <a-input-search
                v-model="formData.id"
                style="width: 100%"
                search-button
                @search="openItemSelector"
                @blur="handleIdBlur"
              >
                <template #button-icon>
                  <icon-search />
                </template>
              </a-input-search>
            </a-form-item>
          </a-col>

          <!-- 物品/装备 信息展示 -->
          <a-col v-if="itemInfo.name" :span="24">
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
            </div>
          </a-col>

          <a-col v-if="formData.type === 5" :span="24">
            <a-form-item
              field="quantity"
              :label="$t('account.player.form.quantity')"
            >
              <a-input-number v-model="formData.quantity" style="width: 100%" />
            </a-form-item>
          </a-col>

          <a-col :span="24">
            <a-form-item field="owner" :label="$t('account.player.form.owner')">
              <a-input v-model="formData.owner" style="width: 100%" />
            </a-form-item>
          </a-col>
          <a-col :span="24">
            <a-form-item
              field="expireType"
              :label="$t('account.player.form.expire.type')"
            >
              <a-radio-group v-model="formData.expireType" type="button">
                <a-radio :value="0">{{
                  $t('account.player.form.expire.permanent')
                }}</a-radio>
                <a-radio :value="1">{{
                  $t('account.player.form.expire.minutes')
                }}</a-radio>
                <a-radio :value="2">{{
                  $t('account.player.form.expire.date')
                }}</a-radio>
              </a-radio-group>
            </a-form-item>
          </a-col>
          <a-col v-if="formData.expireType === 1" :span="24">
            <a-form-item
              field="expire"
              :label="
                isFlaggedAsLock
                  ? $t('account.player.form.expire.lock')
                  : $t('account.player.form.expire')
              "
            >
              <a-input-number
                v-model="formData.expire"
                :placeholder="$t('account.player.form.expire.placeholder')"
                style="width: 100%"
              />
            </a-form-item>
          </a-col>
          <a-col v-if="formData.expireType === 2" :span="24">
            <a-form-item
              field="expireDate"
              :label="
                isFlaggedAsLock
                  ? $t('account.player.form.expire.lock')
                  : $t('account.player.form.expire')
              "
            >
              <a-date-picker
                v-model="formData.expireDate"
                show-time
                format="YYYY-MM-DD HH:mm:ss"
                style="width: 100%"
              />
            </a-form-item>
          </a-col>
          <a-col :span="24">
            <a-form-item field="flag" :label="$t('account.player.form.flag')">
              <a-select
                v-model="formData.flag"
                multiple
                style="width: 100%"
                :max-tag-count="3"
              >
                <a-option :value="0x01">{{
                  $t('account.player.form.flag.lock')
                }}</a-option>
                <a-option :value="0x02">{{
                  $t('account.player.form.flag.spikes')
                }}</a-option>
                <a-option :value="0x04">{{
                  $t('account.player.form.flag.cold')
                }}</a-option>
                <a-option :value="0x08">{{
                  $t('account.player.form.flag.untradeable')
                }}</a-option>
                <a-option :value="0x10">{{
                  $t('account.player.form.flag.karma')
                }}</a-option>
                <a-option :value="0x80">{{
                  $t('account.player.form.flag.pet_come')
                }}</a-option>
                <a-option :value="0x100">{{
                  $t('account.player.form.flag.account_sharing')
                }}</a-option>
                <a-option :value="0x200">{{
                  $t('account.player.form.flag.merge_untradeable')
                }}</a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <template v-if="formData.type === 6">
            <a-col :span="12">
              <a-form-item field="str" :label="$t('account.player.form.str')">
                <a-input-number v-model="formData.str" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="dex" :label="$t('account.player.form.dex')">
                <a-input-number v-model="formData.dex" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="int" :label="$t('account.player.form.int')">
                <a-input-number v-model="formData.int" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="luk" :label="$t('account.player.form.luk')">
                <a-input-number v-model="formData.luk" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="hp" :label="$t('account.player.form.hp')">
                <a-input-number v-model="formData.hp" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="mp" :label="$t('account.player.form.mp')">
                <a-input-number v-model="formData.mp" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="pAtk" :label="$t('account.player.form.pAtk')">
                <a-input-number v-model="formData.pAtk" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="mAtk" :label="$t('account.player.form.mAtk')">
                <a-input-number v-model="formData.mAtk" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="pDef" :label="$t('account.player.form.pDef')">
                <a-input-number v-model="formData.pDef" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="mDef" :label="$t('account.player.form.mDef')">
                <a-input-number v-model="formData.mDef" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="acc" :label="$t('account.player.form.acc')">
                <a-input-number v-model="formData.acc" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="avoid"
                :label="$t('account.player.form.avoid')"
              >
                <a-input-number v-model="formData.avoid" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="hands"
                :label="$t('account.player.form.hands')"
              >
                <a-input-number v-model="formData.hands" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="speed"
                :label="$t('account.player.form.speed')"
              >
                <a-input-number v-model="formData.speed" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="jump" :label="$t('account.player.form.jump')">
                <a-input-number v-model="formData.jump" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="level"
                :label="$t('account.player.form.level')"
              >
                <a-input-number v-model="formData.level" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="itemLevel"
                :label="$t('account.player.form.itemLevel')"
              >
                <a-input-number
                  v-model="formData.itemLevel"
                  style="width: 100%"
                />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="upgradeSlot"
                :label="$t('account.player.form.upgradeSlot')"
              >
                <a-input-number
                  v-model="formData.upgradeSlot"
                  style="width: 100%"
                />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="vicious"
                :label="$t('account.player.form.vicious')"
              >
                <a-input-number
                  v-model="formData.vicious"
                  style="width: 100%"
                />
              </a-form-item>
            </a-col>
          </template>
        </a-row>
      </template>
    </a-form>
    <ItemSelector
      v-model:visible="itemSelectorVisible"
      :initial-id="formData.id"
      @select="handleItemSelect"
    />
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, computed, watch } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import {
    GiveForm,
    givePlayerSrc,
    getEquInitialInfo,
    getItemInitialInfo,
  } from '@/api/player';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import ItemSelector from '@/components/ItemSelector/index.vue';

  const props = defineProps<{
    visible: boolean;
    title: string;
    initialData: GiveForm;
    isEditMode?: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'success', 'submit']);

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const formData = ref<GiveForm>({ ...props.initialData });
  const itemInfo = reactive({
    name: '',
    desc: '',
  });
  const itemIconUrl = ref('');
  const lastFetchedId = ref<number | undefined>(undefined);
  const itemSelectorVisible = ref(false);

  const isFlaggedAsLock = computed(() => {
    return (
      Array.isArray(formData.value.flag) && formData.value.flag.includes(0x01)
    );
  });

  const handleIdBlur = async () => {
    if (!formData.value.id) {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';
      lastFetchedId.value = undefined;
      return;
    }

    if (formData.value.id === lastFetchedId.value) {
      return;
    }
    lastFetchedId.value = formData.value.id;

    setLoading(true);
    try {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';

      if (formData.value.type === 6) {
        const { data } = await getEquInitialInfo(formData.value.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;
        if (equipData) {
          itemInfo.name = equipData.name;
          itemInfo.desc = equipData.desc;
          itemIconUrl.value = getIconUrl('item', formData.value.id);

          if (!props.isEditMode || !formData.value.str) {
            formData.value.str = equipData.str || 0;
            formData.value.dex = equipData.dex || 0;
            formData.value.int = equipData.int || 0;
            formData.value.luk = equipData.luk || 0;
            formData.value.hp = equipData.hp || 0;
            formData.value.mp = equipData.mp || 0;
            formData.value.pAtk = equipData.pAtk || 0;
            formData.value.mAtk = equipData.mAtk || 0;
            formData.value.pDef = equipData.pDef || 0;
            formData.value.mDef = equipData.mDef || 0;
            formData.value.acc = equipData.acc || 0;
            formData.value.avoid = equipData.avoid || 0;
            formData.value.hands = equipData.hands || 0;
            formData.value.speed = equipData.speed || 0;
            formData.value.jump = equipData.jump || 0;
            formData.value.upgradeSlot = equipData.upgradeSlot || 0;
            formData.value.level = equipData.level || 0;
            formData.value.itemLevel = equipData.itemLevel || 1;
            formData.value.vicious = equipData.vicious || 0;
          }

          if (!props.isEditMode) {
            Message.success(t('account.player.equip.success'));
          }
        } else {
          // 如果不是装备，尝试作为普通物品查询
          try {
            const { data: itemData } = await getItemInitialInfo(
              formData.value.id
            );
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const iData = itemData as any;
            if (iData) {
              // 如果找到了物品信息，说明用户输入的是物品ID，但当前类型选的是装备
              // 这里可以提示用户，或者自动切换类型（如果需求允许）
              // 按照需求1：如果不是装备，不要提示只允许方法装备这个提示
              // 这里原本的逻辑是 Message.warning(t('account.player.equip.warning'));
              // 我们可以静默失败，或者给一个更通用的提示，或者什么都不做
              // 但为了用户体验，如果确实没找到装备信息，还是应该提示一下，只是不要误导说“只允许发放装备”
              // 如果API返回空，说明既不是装备也不是物品，或者ID不存在
              Message.warning(t('account.player.equip.warning'));
            }
          } catch (e) {
            // 忽略
            Message.warning(t('account.player.equip.warning'));
          }
        }
      } else if (formData.value.type === 5) {
        const { data } = await getItemInitialInfo(formData.value.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const itemData = data as any;
        if (itemData) {
          itemInfo.name = itemData.name;
          itemInfo.desc = itemData.desc;
          itemIconUrl.value = getIconUrl('item', formData.value.id);
          if (!props.isEditMode) {
            Message.success(t('account.player.item.success'));
          }
        } else {
          Message.warning(t('account.player.item.warning'));
        }
      }
    } catch (error) {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        formData.value = { ...props.initialData };
        itemInfo.name = '';
        itemInfo.desc = '';
        itemIconUrl.value = '';
        lastFetchedId.value = undefined;
        if (formData.value.id) {
          handleIdBlur();
        }
      }
    }
  );

  watch(
    () => formData.value.expireType,
    () => {
      formData.value.expire = undefined;
      formData.value.expireDate = undefined;
    }
  );

  const handleTypeChange = () => {
    formData.value.id = undefined;
    itemInfo.name = '';
    itemInfo.desc = '';
    itemIconUrl.value = '';
    lastFetchedId.value = undefined;
    if (formData.value.type !== 6) {
      formData.value.str = undefined;
      formData.value.dex = undefined;
      formData.value.int = undefined;
      formData.value.luk = undefined;
      formData.value.hp = undefined;
      formData.value.mp = undefined;
      formData.value.pAtk = undefined;
      formData.value.mAtk = undefined;
      formData.value.pDef = undefined;
      formData.value.mDef = undefined;
      formData.value.acc = undefined;
      formData.value.avoid = undefined;
      formData.value.hands = undefined;
      formData.value.speed = undefined;
      formData.value.jump = undefined;
      formData.value.upgradeSlot = undefined;
      formData.value.level = undefined;
      formData.value.itemLevel = undefined;
      formData.value.vicious = undefined;
    }
  };

  const submitClick = async (done: any) => {
    if (props.isEditMode) {
      emit('submit', formData.value);
      done(true);
      return;
    }

    setLoading(true);
    try {
      const submitData = { ...formData.value };
      if (submitData.type === 6 || submitData.type === 5) {
        if (submitData.expireType === 0) {
          submitData.expire = -1;
        } else if (submitData.expireType === 2 && submitData.expireDate) {
          const now = new Date().getTime();
          const target = new Date(submitData.expireDate).getTime();
          const diffMinutes = Math.floor((target - now) / (1000 * 60));
          submitData.expire = diffMinutes > 0 ? diffMinutes : 0;
        }
        if (Array.isArray(submitData.flag)) {
          // eslint-disable-next-line no-bitwise
          submitData.flag = submitData.flag.reduce((acc, cur) => acc | cur, 0);
        }
      }
      await givePlayerSrc(submitData);
      Message.success(t('message.success'));
      emit('success');
      done(true);
    } catch (error) {
      done(false);
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    visibleModel.value = false;
  };

  const openItemSelector = () => {
    itemSelectorVisible.value = true;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleItemSelect = (item: any) => {
    formData.value.id = item.id;
    handleIdBlur();
    itemSelectorVisible.value = false;
  };
</script>

<style scoped>
  .form-aligned :deep(.arco-form-item-label-col) {
    flex: 0 0 120px !important;
    width: 120px !important;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    white-space: nowrap;
    padding-right: 12px;
  }
  .form-aligned :deep(.arco-form-item-wrapper-col) {
    flex: 1;
    width: auto;
    max-width: none;
  }
  .item-info-container {
    display: flex;
    margin-bottom: 20px;
    border: 1px solid var(--color-neutral-3);
    padding: 10px;
    border-radius: 4px;
    margin-left: 120px;
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
  }
</style>
