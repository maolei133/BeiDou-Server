<template>
  <a-modal
    :visible="visible"
    :title="title"
    :ok-loading="submitting"
    :ok-text="$t('account.player.button.jail')"
    @cancel="handleCancel"
    @before-ok="handleOk"
  >
    <a-form
      ref="formRef"
      :model="form"
      :label-col-props="{ span: 7 }"
      :wrapper-col-props="{ span: 17 }"
    >
      <a-form-item field="minutes" :label="$t('account.player.jail.minutes')">
        <a-input-number
          v-model="form.minutes"
          :min="1"
          :max="1440"
          style="width: 100%"
        />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, watch, computed } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { imprisonPlayer } from '@/api/player';

  const props = defineProps<{
    visible: boolean;
    playerId: number;
    playerName: string;
  }>();

  const emit = defineEmits(['update:visible', 'success']);

  const { t } = useI18n();

  const title = computed(() =>
    t('account.player.jail.title', {
      name: props.playerName || '',
    })
  );

  const formRef = ref();
  const submitting = ref(false);
  const form = ref({ minutes: 5 });

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        form.value = { minutes: 5 };
        submitting.value = false;
      }
    }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleOk = async () => {
    if (submitting.value) return false;
    submitting.value = true;
    try {
      await imprisonPlayer({
        playerId: props.playerId,
        minutes: form.value.minutes,
      });
      emit('success');
      emit('update:visible', false);
      return true;
    } catch {
      return false;
    } finally {
      submitting.value = false;
    }
  };
</script>
