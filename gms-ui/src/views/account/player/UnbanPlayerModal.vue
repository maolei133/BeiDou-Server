<template>
  <a-modal
    :visible="visible"
    :title="$t('account.player.unban.confirm.title')"
    :ok-loading="loading"
    :mask-closable="false"
    :esc-to-close="false"
    :ok-text="$t('account.player.button.unban')"
    @cancel="handleCancel"
    @before-ok="handleSubmit"
  >
    <div style="margin-bottom: 16px">
      {{ $t('account.player.unban.confirm.content', { name: player?.name }) }}
    </div>
    <a-form ref="formRef" :model="form">
      <a-form-item :label="$t('account.player.unban.options')">
        <a-space direction="vertical">
          <a-checkbox v-model="form.unbanIp">
            {{ $t('account.player.unban.options.ip') }}
          </a-checkbox>
          <a-select
            v-if="form.unbanIp"
            v-model="form.ips"
            multiple
            :placeholder="$t('account.player.ban.options.ip.placeholder')"
            style="width: 300px"
          >
            <a-option v-for="ip in banInfo.ips" :key="ip" :value="ip">
              {{ ip }}
            </a-option>
          </a-select>
          <a-checkbox v-model="form.unbanMac">
            {{ $t('account.player.unban.options.mac') }}
          </a-checkbox>
          <a-select
            v-if="form.unbanMac"
            v-model="form.macs"
            multiple
            :placeholder="$t('account.player.ban.options.mac.placeholder')"
            style="width: 300px"
          >
            <a-option v-for="mac in banInfo.macs" :key="mac" :value="mac">
              {{ mac }}
            </a-option>
          </a-select>
          <a-checkbox v-model="form.unbanHwid">
            {{ $t('account.player.unban.options.hwid') }}
          </a-checkbox>
          <div v-if="form.unbanHwid && banInfo.hwid" style="color: gray">
            HWID: {{ banInfo.hwid }}
          </div>
        </a-space>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, watch } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import {
    OnlinePlayer,
    unbanPlayer,
    getBanInfo,
    BanInfoRtn,
  } from '@/api/player';

  const props = defineProps<{
    visible: boolean;
    player: OnlinePlayer | null;
    loading: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const { t } = useI18n();
  const formRef = ref();
  const submitting = ref(false);

  const form = ref({
    unbanIp: false,
    unbanMac: false,
    unbanHwid: false,
    ips: [] as string[],
    macs: [] as string[],
  });

  const banInfo = ref<BanInfoRtn>({
    ips: [],
    macs: [],
    hwid: '',
  });

  const fetchBanInfo = async () => {
    if (props.player) {
      try {
        const { data } = await getBanInfo(props.player.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const info = data as any;
        banInfo.value = info;
        // 默认全选
        form.value.ips = info.ips || [];
        form.value.macs = info.macs || [];
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
          unbanIp: false,
          unbanMac: false,
          unbanHwid: false,
          ips: [],
          macs: [],
        };
        banInfo.value = { ips: [], macs: [], hwid: '' };
        submitting.value = false;
        fetchBanInfo();
      }
    }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleSubmit = async () => {
    if (!props.player || submitting.value) return false;

    submitting.value = true;
    try {
      await unbanPlayer({
        id: props.player.id,
        ...form.value,
      });
      Message.success(t('message.success'));
      emit('success');
      emit('update:visible', false);
      return true;
    } catch (error) {
      return false;
    } finally {
      submitting.value = false;
    }
  };
</script>
