<template>
  <a-modal
    v-model:visible="visibleModel"
    title="发放快递"
    width="600px"
    @cancel="handleCancel"
    @before-ok="handleBeforeOk"
  >
    <a-form ref="formRef" :model="form" :rules="rules" layout="vertical">
      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item field="isAll" label="发送对象">
            <a-radio-group v-model="form.isAll" type="button">
              <a-radio :value="false">单人</a-radio>
              <a-radio :value="true">全服</a-radio>
            </a-radio-group>
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item field="quick" label="配送类型">
            <a-switch v-model="form.quick">
              <template #checked>快速</template>
              <template #unchecked>普通</template>
            </a-switch>
          </a-form-item>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item
            v-if="!form.isAll"
            field="receiverName"
            label="收件人角色名"
            :rules="[{ required: true, message: '请输入收件人角色名' }]"
          >
            <a-input v-model="form.receiverName" placeholder="请输入角色名" />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item field="senderName" label="发件人名称">
            <a-input v-model="form.senderName" placeholder="默认: 管理员" />
          </a-form-item>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item field="mesos" label="金币">
            <a-input-number
              v-model="form.mesos"
              placeholder="请输入金币数量"
              :min="0"
              :max="2147483647"
            />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item field="expireDays" label="过期时间">
            <a-input-group>
              <a-input-number
                v-model="form.expireDays"
                placeholder="天数"
                :min="1"
                style="width: 120px"
              />
              <a-date-picker
                v-model="expireDate"
                show-time
                format="YYYY-MM-DD HH:mm:ss"
                style="flex: 1"
                placeholder="选择日期"
                @change="handleDateChange"
              />
            </a-input-group>
          </a-form-item>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item field="itemId" label="物品ID">
            <a-input-number
              v-model="form.itemId"
              placeholder="请输入物品ID"
              @blur="handleIdBlur"
            />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item field="quantity" label="物品数量">
            <a-input-number
              v-model="form.quantity"
              placeholder="请输入物品数量"
              :min="1"
              :max="32767"
            />
          </a-form-item>
        </a-col>
      </a-row>

      <!-- 物品信息展示 -->
      <a-row v-if="itemInfo.name" :gutter="16" style="margin-bottom: 20px">
        <a-col :span="24">
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
      </a-row>

      <a-form-item field="message" label="留言">
        <a-textarea
          v-model="form.message"
          placeholder="请输入留言内容"
          :max-length="100"
          show-word-limit
        />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, watch, computed } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { sendDueyPackage, SendDueyReq } from '@/api/duey';
  import { getEquInitialInfo, getItemInitialInfo } from '@/api/player';
  import { getIconUrl } from '@/utils/mapleStoryAPI';

  const props = defineProps<{
    visible: boolean;
    defaultReceiver?: string;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const formRef = ref();
  const form = reactive<SendDueyReq>({
    isAll: false,
    receiverName: '',
    mesos: 0,
    itemId: undefined,
    quantity: 1,
    message: '',
    quick: false,
    senderName: '',
    expireDays: 30,
    expireTime: undefined,
  });

  const expireDate = ref<string | undefined>(undefined);

  const itemInfo = reactive({
    name: '',
    desc: '',
  });
  const itemIconUrl = ref('');
  const lastFetchedId = ref<number | undefined>(undefined);

  const rules = {
    receiverName: [{ required: true, message: '请输入收件人' }],
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        if (props.defaultReceiver) {
          form.receiverName = props.defaultReceiver;
        }
      } else {
        formRef.value?.resetFields();
        form.isAll = false;
        form.mesos = 0;
        form.itemId = undefined;
        form.quantity = 1;
        form.message = '';
        form.quick = false;
        form.senderName = '';
        form.expireDays = 30;
        form.expireTime = undefined;
        expireDate.value = undefined;
        itemInfo.name = '';
        itemInfo.desc = '';
        itemIconUrl.value = '';
        lastFetchedId.value = undefined;
      }
    }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleDateChange = (dateString: string | undefined) => {
    if (dateString) {
      form.expireTime = new Date(dateString).getTime();
      form.expireDays = undefined; // 如果选择了具体日期，清除天数
    } else {
      form.expireTime = undefined;
    }
  };

  // 监听天数变化，如果输入了天数，清除具体日期
  watch(
    () => form.expireDays,
    (val) => {
      if (val) {
        expireDate.value = undefined;
        form.expireTime = undefined;
      }
    }
  );

  const handleIdBlur = async () => {
    if (!form.itemId) {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';
      lastFetchedId.value = undefined;
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

      // 尝试作为装备查询
      try {
        const { data } = await getEquInitialInfo(form.itemId);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;
        if (equipData) {
          itemInfo.name = equipData.name;
          itemInfo.desc = equipData.desc;
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

  const handleBeforeOk = async (done: any) => {
    const res = await formRef.value?.validate();
    if (res) {
      done(false);
      return;
    }

    try {
      await sendDueyPackage(form);
      Message.success('发送成功');
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
