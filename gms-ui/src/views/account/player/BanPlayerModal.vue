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
      <a-form-item field="duration" :label="$t('account.player.ban.duration')">
        <a-input-number
          v-model="form.duration"
          placeholder="留空或0为永久封禁"
          :min="0"
        >
          <template #suffix>分钟</template>
        </a-input-number>
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
            placeholder="请输入通知内容"
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
  const form = ref({
    reason: '',
    duration: undefined as number | undefined,
    banIp: false,
    banMac: false,
    banHwid: false,
    notify: false,
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
          banIp: false,
          banMac: false,
          banHwid: false,
          notify: false,
          notifyContent: '',
          ips: [],
          macs: [],
        };
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
