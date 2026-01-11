<template>
  <a-modal
    :visible="visible"
    :title="title"
    :ok-loading="loading"
    :mask-closable="false"
    :esc-to-close="false"
    :ok-text="$t('account.player.button.ban')"
    @cancel="handleCancel"
    @before-ok="handleSubmit"
  >
    <a-form ref="formRef" :model="form">
      <a-form-item
        field="reason"
        :label="$t('account.player.ban.reason')"
        :rules="[{ required: true, message: '请输入封禁原因' }]"
      >
        <a-input v-model="form.reason" placeholder="请输入封禁原因" />
      </a-form-item>
      <a-form-item :label="$t('account.player.ban.duration')">
        <a-radio-group v-model="banType" type="button">
          <a-radio value="permanent">永久</a-radio>
          <a-radio value="duration">时长</a-radio>
          <a-radio value="date">日期</a-radio>
        </a-radio-group>
      </a-form-item>
      <a-form-item v-if="banType === 'duration'" field="duration" label="时长">
        <a-input-number
          v-model="form.duration"
          placeholder="请输入封禁分钟数"
          :min="1"
        >
          <template #suffix>分钟</template>
        </a-input-number>
      </a-form-item>
      <a-form-item v-if="banType === 'date'" field="banUntil" label="解封时间">
        <a-date-picker
          v-model="banUntilDate"
          show-time
          format="YYYY-MM-DD HH:mm:ss"
          style="width: 100%"
        />
      </a-form-item>
      <a-form-item :label="$t('account.player.ban.options')">
        <a-space direction="vertical">
          <a-checkbox v-model="form.banIp">封禁 IP</a-checkbox>
          <a-select
            v-if="form.banIp && !all"
            v-model="form.ips"
            multiple
            placeholder="选择要封禁的IP"
            style="width: 300px"
          >
            <a-option v-for="ip in banInfo.ips" :key="ip" :value="ip">
              {{ ip }}
            </a-option>
          </a-select>
          <a-checkbox v-model="form.banMac">封禁 MAC</a-checkbox>
          <a-select
            v-if="form.banMac && !all"
            v-model="form.macs"
            multiple
            placeholder="选择要封禁的MAC"
            style="width: 300px"
          >
            <a-option v-for="mac in banInfo.macs" :key="mac" :value="mac">
              {{ mac }}
            </a-option>
          </a-select>
          <a-checkbox v-model="form.banHwid">封禁 HWID</a-checkbox>
          <div v-if="form.banHwid && !all && banInfo.hwid" style="color: gray">
            HWID: {{ banInfo.hwid }}
          </div>
        </a-space>
      </a-form-item>
      <a-form-item :label="$t('account.player.ban.notify')">
        <a-space direction="vertical" style="width: 100%">
          <a-checkbox v-model="form.notify">全服通知</a-checkbox>
          <a-textarea
            v-if="form.notify"
            v-model="form.notifyContent"
            placeholder="请输入通知内容，默认使用封禁原因"
            auto-size
          />
        </a-space>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, watch, computed } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import {
    OnlinePlayer,
    banPlayer,
    getBanInfo,
    BanInfoRtn,
  } from '@/api/player';

  const props = defineProps<{
    visible: boolean;
    player: OnlinePlayer | null;
    all: boolean;
    loading: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const { t } = useI18n();
  const formRef = ref();
  const banType = ref('permanent');
  const banUntilDate = ref<string | undefined>(undefined);

  const form = ref({
    reason: '',
    duration: undefined as number | undefined,
    banUntil: undefined as number | undefined,
    banIp: false,
    banMac: false,
    banHwid: false,
    notify: true,
    notifyContent: '',
    ips: [] as string[],
    macs: [] as string[],
  });

  const banInfo = ref<BanInfoRtn>({
    ips: [],
    macs: [],
    hwid: '',
  });

  const title = computed(() => {
    if (props.all) {
      return '全服封禁';
    }
    return `封禁玩家: ${props.player?.name || ''}`;
  });

  const fetchBanInfo = async () => {
    if (props.player && !props.all) {
      try {
        const { data } = await getBanInfo(props.player.id);
        banInfo.value = data;
        // 默认全选
        form.value.ips = data.ips;
        form.value.macs = data.macs;
      } catch (error) {
        // ignore
      }
    }
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        form.value = {
          reason: '',
          duration: undefined,
          banUntil: undefined,
          banIp: false,
          banMac: false,
          banHwid: false,
          notify: true,
          notifyContent: '',
          ips: [],
          macs: [],
        };
        banType.value = 'permanent';
        banUntilDate.value = undefined;
        banInfo.value = { ips: [], macs: [], hwid: '' };
        fetchBanInfo();
      }
    }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleSubmit = async () => {
    const res = await formRef.value?.validate();
    if (res) return false;

    // 仅临时封禁时，不能永久封禁账号（这里逻辑有点绕，其实是如果选择了时长或日期，就不是永久封禁）
    // 但需求是“仅临时封禁，则不能永久封禁账号”，这通常意味着如果选择了时长，后端不应该把账号设为永久封禁
    // 前端只需要传正确的参数即可

    if (banType.value === 'permanent') {
      form.value.duration = 0;
      form.value.banUntil = undefined;
    } else if (banType.value === 'duration') {
      if (!form.value.duration || form.value.duration <= 0) {
        Message.warning('请输入有效的封禁时长');
        return false;
      }
      form.value.banUntil = undefined;
    } else if (banType.value === 'date') {
      if (!banUntilDate.value) {
        Message.warning('请选择解封时间');
        return false;
      }
      form.value.banUntil = new Date(banUntilDate.value).getTime();
      form.value.duration = undefined;
    }

    try {
      await banPlayer({
        ids: props.player ? [props.player.id] : [],
        all: props.all,
        ...form.value,
      });
      Message.success(t('message.success'));
      emit('success');
      return true;
    } catch (error) {
      return false;
    }
  };
</script>
