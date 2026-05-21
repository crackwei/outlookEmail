        /* global accountsCache, currentGroupId, escapeHtml, groups, handleApiError, hideModal, invalidateRefreshTokenPreview, isTempEmailGroup, loadAccountsByGroup, loadGroups, oauthPreviewAccount, renderRefreshTokenPreview, setModalVisible, showModal, showToast, updateGroupSelects */

        // ==================== 工具函数 ====================

        // 格式化日期
        function formatDate(dateStr) {
            if (!dateStr) return '';
            try {
                let normalizedDate = dateStr;
                if (typeof dateStr === 'number' || /^\d+$/.test(String(dateStr))) {
                    const timestamp = Number(dateStr);
                    normalizedDate = timestamp < 1000000000000 ? timestamp * 1000 : timestamp;
                }

                const date = new Date(normalizedDate);
                if (isNaN(date.getTime())) return dateStr;

                const now = new Date();
                const timeZone = getAppTimeZone();
                const dateKeyFormatter = new Intl.DateTimeFormat('en-CA', {
                    timeZone,
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit'
                });
                const isToday = dateKeyFormatter.format(date) === dateKeyFormatter.format(now);

                if (isToday) {
                    return '今天 ' + date.toLocaleTimeString('zh-CN', {
                        timeZone,
                        hour: '2-digit',
                        minute: '2-digit'
                    });
                } else {
                    return date.toLocaleDateString('zh-CN', {
                        timeZone,
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    }) + ' ' + date.toLocaleTimeString('zh-CN', {
                        timeZone,
                        hour: '2-digit',
                        minute: '2-digit'
                    });
                }
            } catch (e) {
                return dateStr;
            }
        }

        // ==================== OAuth Refresh Token 相关 ====================

        function invalidateRefreshTokenPreview() {
            oauthPreviewAccount = null;
            const resultEl = document.getElementById('refreshTokenResult');
            if (resultEl) {
                resultEl.style.display = 'none';
            }
        }

        function renderRefreshTokenPreview() {
            if (!oauthPreviewAccount) {
                invalidateRefreshTokenPreview();
                return;
            }
            const resultEl = document.getElementById('refreshTokenResult');
            const saveBtn = document.getElementById('saveTokenAccountBtn');
            const group = groups.find(item => item.id === oauthPreviewAccount.group_id);
            const fallbackGroupId = Number.parseInt(String(oauthPreviewAccount.group_id ?? ''), 10);
            document.getElementById('oauthPreviewEmail').value = oauthPreviewAccount.email || '';
            document.getElementById('oauthPreviewPassword').value = oauthPreviewAccount.password || '';
            document.getElementById('oauthPreviewClientId').value = oauthPreviewAccount.client_id || '';
            document.getElementById('oauthPreviewGroup').value = group?.name || (Number.isFinite(fallbackGroupId) ? String(fallbackGroupId) : '');
            document.getElementById('oauthPreviewRefreshToken').value = oauthPreviewAccount.refresh_token || '';
            if (resultEl) {
                resultEl.style.display = 'block';
            }
        }

        // 显示获取 Refresh Token 模态框
        async function showGetRefreshTokenModal() {
            showModal('getRefreshTokenModal');

            // 重置表单
            document.getElementById('oauthEmailInput').value = '';
            document.getElementById('oauthPasswordInput').value = '';
            document.getElementById('redirectUrlInput').value = '';
            document.getElementById('oauthForwardEnabled').checked = false;
            invalidateRefreshTokenPreview();

            // 重置按钮状态
            const btn = document.getElementById('exchangeTokenBtn');
            btn.disabled = false;
            btn.textContent = '换取并预览';
            btn.style.display = '';
            const saveBtn = document.getElementById('saveTokenAccountBtn');
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.textContent = '直接保存（自动换取）';
            }

            const groupSelect = document.getElementById('tokenSaveGroupSelect');
            if (groupSelect) {
                const nonTempGroups = groups.filter(group => group.name !== '临时邮箱');
                const fallbackGroupId = (!isTempEmailGroup && currentGroupId && nonTempGroups.find(group => group.id === currentGroupId))
                    ? currentGroupId
                    : (nonTempGroups[0]?.id || '');
                if (fallbackGroupId) {
                    groupSelect.value = fallbackGroupId;
                }
            }

            // 获取授权 URL
            try {
                const response = await fetch('/api/oauth/auth-url');
                const data = await response.json();

                if (data.success) {
                    document.getElementById('authUrlInput').value = data.auth_url;
                } else {
                    showToast('获取授权链接失败', 'error');
                }
            } catch (error) {
                showToast('获取授权链接失败', 'error');
            }
        }

        // 隐藏获取 Refresh Token 模态框
        function hideGetRefreshTokenModal() {
            hideModal('getRefreshTokenModal');
        }

        // 复制授权 URL
        function copyAuthUrl() {
            const input = document.getElementById('authUrlInput');
            input.select();
            document.execCommand('copy');
            showToast('授权链接已复制到剪贴板', 'success');
        }

        // 打开授权 URL
        function openAuthUrl() {
            const url = document.getElementById('authUrlInput').value;
            if (url) {
                window.open(url, '_blank');
                showToast('已在新窗口打开授权页面', 'info');
            }
        }

        // 换取 Token
        async function exchangeToken(options = {}) {
            const { silentSuccess = false, keepSavingState = false } = options;
            const email = document.getElementById('oauthEmailInput').value.trim();
            const password = document.getElementById('oauthPasswordInput').value;
            const redirectUrl = document.getElementById('redirectUrlInput').value.trim();
            const groupId = parseInt(document.getElementById('tokenSaveGroupSelect')?.value || '0', 10);
            const forwardEnabled = !!document.getElementById('oauthForwardEnabled')?.checked;

            if (!redirectUrl) {
                showToast('请先粘贴授权后的完整 URL', 'error');
                return;
            }

            const btn = document.getElementById('exchangeTokenBtn');
            const saveBtn = document.getElementById('saveTokenAccountBtn');
            btn.disabled = true;
            if (!keepSavingState && saveBtn) {
                saveBtn.disabled = true;
            }
            btn.textContent = '⏳ 预览中...';

            try {
                const response = await fetch('/api/oauth/exchange-token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        redirected_url: redirectUrl
                    })
                });

                const data = await response.json();

                if (data.success) {
                    oauthPreviewAccount = {
                        email,
                        password,
                        client_id: data.client_id,
                        refresh_token: data.refresh_token,
                        group_id: groupId,
                        forward_enabled: forwardEnabled
                    };
                    renderRefreshTokenPreview();

                    if (!silentSuccess) {
                        showToast('✅ Refresh Token 获取成功！', 'success');
                    }

                    // 重置按钮状态（不隐藏，允许重复使用）
                    btn.disabled = false;
                    if (!keepSavingState && saveBtn) {
                        saveBtn.disabled = false;
                    }
                    btn.textContent = '换取并预览';
                    return true;
                } else {
                    handleApiError(data, '换取 Token 失败');
                    btn.disabled = false;
                    if (!keepSavingState && saveBtn) {
                        saveBtn.disabled = false;
                    }
                    btn.textContent = '换取并预览';
                    return false;
                }
            } catch (error) {
                showToast('换取 Token 失败: ' + error.message, 'error');
                btn.disabled = false;
                if (!keepSavingState && saveBtn) {
                    saveBtn.disabled = false;
                }
                btn.textContent = '换取并预览';
                return false;
            }
        }

        async function saveTokenAccount() {
            if (!oauthPreviewAccount) {
                const exchanged = await exchangeToken({ silentSuccess: true, keepSavingState: true });
                if (!exchanged || !oauthPreviewAccount) {
                    return;
                }
            }

            if (!oauthPreviewAccount.email || !oauthPreviewAccount.password) {
                showToast('保存账号前请先填写邮箱账号和密码', 'error');
                return;
            }

            if (!oauthPreviewAccount.group_id) {
                showToast('保存账号前请选择目标分组', 'error');
                return;
            }

            const saveBtn = document.getElementById('saveTokenAccountBtn');
            const exchangeBtn = document.getElementById('exchangeTokenBtn');
            saveBtn.disabled = true;
            exchangeBtn.disabled = true;
            saveBtn.textContent = '保存中...';

            try {
                const accountString = [
                    oauthPreviewAccount.email,
                    oauthPreviewAccount.password,
                    oauthPreviewAccount.client_id,
                    oauthPreviewAccount.refresh_token
                ].join('----');

                const response = await fetch('/api/accounts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        account_string: accountString,
                        group_id: oauthPreviewAccount.group_id,
                        provider: 'outlook',
                        forward_enabled: !!oauthPreviewAccount.forward_enabled
                    })
                });

                const data = await response.json();
                if (data.success) {
                    showToast(data.message || '账号已保存', 'success');
                    currentGroupId = oauthPreviewAccount.group_id;
                    await loadGroups();
                    hideGetRefreshTokenModal();
                } else {
                    handleApiError(data, '保存账号失败');
                }
            } catch (error) {
                showToast('保存账号失败', 'error');
            } finally {
                exchangeBtn.disabled = false;
                saveBtn.disabled = false;
                saveBtn.textContent = '直接保存（自动换取）';
            }
        }

        function getPreferredRegularGroupId(selectId) {
            const regularGroups = groups.filter(group => group.name !== '临时邮箱');
            if (!regularGroups.length) {
                return '';
            }
            const currentSelect = document.getElementById(selectId);
            const currentValue = parseInt(currentSelect?.value || '0', 10);
            if (currentValue && regularGroups.find(group => group.id === currentValue)) {
                return currentValue;
            }
            if (!isTempEmailGroup && currentGroupId && regularGroups.find(group => group.id === currentGroupId)) {
                return currentGroupId;
            }
            return regularGroups[0].id;
        }

        function resetBatchOutlookTokenResult() {
            const resultEl = document.getElementById('batchTokenResult');
            const summaryEl = document.getElementById('batchTokenResultSummary');
            const failedGroupEl = document.getElementById('batchTokenFailedGroup');
            const failedOutputEl = document.getElementById('batchTokenFailedOutput');
            const failureListEl = document.getElementById('batchTokenFailureList');
            const invalidListEl = document.getElementById('batchTokenInvalidList');

            if (resultEl) resultEl.style.display = 'none';
            if (summaryEl) summaryEl.innerHTML = '';
            if (failedGroupEl) failedGroupEl.style.display = 'none';
            if (failedOutputEl) failedOutputEl.value = '';
            if (failureListEl) failureListEl.innerHTML = '';
            if (invalidListEl) invalidListEl.innerHTML = '';
        }

        function showBatchOutlookTokenImportModal() {
            const regularGroups = groups.filter(group => group.name !== '临时邮箱');
            if (!regularGroups.length) {
                showToast('请先创建普通邮箱分组', 'error');
                return;
            }

            updateGroupSelects();
            showModal('batchOutlookTokenModal');
            document.getElementById('batchTokenAccountInput').value = '';
            document.getElementById('batchTokenProxyInput').value = '';
            document.getElementById('batchTokenForwardEnabled').checked = false;
            resetBatchOutlookTokenResult();

            const groupSelect = document.getElementById('batchTokenGroupSelect');
            if (groupSelect) {
                groupSelect.value = getPreferredRegularGroupId('batchTokenGroupSelect');
            }

            const startBtn = document.getElementById('batchTokenStartBtn');
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.textContent = '开始换取并入库';
            }
        }

        function hideBatchOutlookTokenImportModal() {
            hideModal('batchOutlookTokenModal');
        }

        function renderBatchOutlookTokenResult(data) {
            const resultEl = document.getElementById('batchTokenResult');
            const summaryEl = document.getElementById('batchTokenResultSummary');
            const failedGroupEl = document.getElementById('batchTokenFailedGroup');
            const failedOutputEl = document.getElementById('batchTokenFailedOutput');
            const failureListEl = document.getElementById('batchTokenFailureList');
            const invalidListEl = document.getElementById('batchTokenInvalidList');
            const failedAccounts = Array.isArray(data.failed_accounts) ? data.failed_accounts : [];
            const invalidLines = Array.isArray(data.invalid_lines) ? data.invalid_lines : [];

            if (summaryEl) {
                summaryEl.innerHTML = `
                    <div class="batch-token-result__title">${escapeHtml(data.message || '批量换 Token 完成')}</div>
                    <div class="batch-token-result__meta">
                        已处理 ${Number(data.processed_count || 0)} 个账号，代理 ${Number(data.proxy_count || 0)} 个，
                        新增 ${Number(data.added_count || 0)} 个，重复 ${Number(data.skipped_count || 0)} 个，
                        失败 ${Number(data.failed_count || 0)} 个。
                    </div>
                `;
            }

            if (failedOutputEl) {
                failedOutputEl.value = failedAccounts.map(item => `${item.email || ''}:${item.password || ''}`).join('\n');
            }
            if (failedGroupEl) {
                failedGroupEl.style.display = failedAccounts.length ? '' : 'none';
            }
            if (failureListEl) {
                failureListEl.innerHTML = failedAccounts.length
                    ? failedAccounts.map(item => `
                        <div class="batch-token-failure-item">
                            <strong>${escapeHtml(item.email || '')}</strong>
                            <span>${escapeHtml(item.error || '换取失败')}</span>
                            <em>${escapeHtml(item.proxy || 'direct')}</em>
                        </div>
                    `).join('')
                    : '';
            }
            if (invalidListEl) {
                invalidListEl.innerHTML = invalidLines.length
                    ? `
                        <div class="batch-token-invalid-title">格式无效</div>
                        ${invalidLines.map(item => `
                            <div class="batch-token-invalid-item">
                                第 ${Number(item.line || 0)} 行：${escapeHtml(item.content || '')}
                            </div>
                        `).join('')}
                    `
                    : '';
            }
            if (resultEl) {
                resultEl.style.display = 'grid';
            }
        }

        async function startBatchOutlookTokenImport() {
            const accountInput = document.getElementById('batchTokenAccountInput').value.trim();
            const proxyInput = document.getElementById('batchTokenProxyInput').value.trim();
            const groupId = parseInt(document.getElementById('batchTokenGroupSelect')?.value || '0', 10);
            const forwardEnabled = !!document.getElementById('batchTokenForwardEnabled')?.checked;
            const startBtn = document.getElementById('batchTokenStartBtn');

            if (!groupId) {
                showToast('请选择目标分组', 'error');
                return;
            }
            if (!accountInput) {
                showToast('请输入账号密码', 'error');
                return;
            }

            resetBatchOutlookTokenResult();
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.textContent = '换取中...';
            }

            try {
                const response = await fetch('/api/accounts/import-outlook-passwords', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        account_string: accountInput,
                        proxy_list: proxyInput,
                        group_id: groupId,
                        forward_enabled: forwardEnabled
                    })
                });
                const data = await response.json();

                if (!response.ok || !data.success) {
                    handleApiError(data, '批量换 Token 失败');
                    return;
                }

                renderBatchOutlookTokenResult(data);
                showToast(data.failed_count ? '批量完成，请查看失败账号' : (data.message || '批量导入完成'), data.failed_count ? 'info' : 'success');

                if (Number(data.added_count || 0) > 0) {
                    delete accountsCache[groupId];
                    currentGroupId = groupId;
                    await loadGroups();
                }
            } catch (error) {
                showToast('批量换 Token 失败: ' + error.message, 'error');
            } finally {
                if (startBtn) {
                    startBtn.disabled = false;
                    startBtn.textContent = '开始换取并入库';
                }
            }
        }
