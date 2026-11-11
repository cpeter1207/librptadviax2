//! Prepared listener storage, owned only by the reserved control transaction.

use super::*;

/// Fully allocated replacement; unchanged numeric admission needs no replacement lifetime.
pub(crate) struct PreparedConfiguration {
    accounts: Vec<Arc<Account>>,
    numeric: Option<(Vec<String>, Arc<Life>)>,
}

impl InboundIaxListener {
    /// Copy/validate first; a failure never changes account, numeric or call admission.
    pub(crate) fn prepare_configuration(
        &self,
        local_nodes: Vec<String>,
        configs: Vec<AccountConfig>,
    ) -> Result<PreparedConfiguration, AccountError> {
        self.validate_accounts(&configs)?;
        if !local_nodes.is_empty() && !valid_local_nodes(&local_nodes) {
            return Err(AccountError::InvalidOptions);
        }
        let accounts = self.prepare_accounts(configs.into_iter().map(Cow::Owned))?;
        let numeric = (self.local_nodes != local_nodes).then(|| (local_nodes, Life::new()));
        Ok(PreparedConfiguration { accounts, numeric })
    }

    /// Reserve only after the whole batch has completed all fallible preparation.
    pub(crate) fn reserve_configuration(&mut self) {
        self.configuration_reserved = true;
    }

    /// Commit or abort under all batch locks; this path cannot allocate or call foreign code.
    pub(crate) fn finish_configuration(&mut self, prepared: Option<PreparedConfiguration>) {
        if let Some(prepared) = prepared {
            self.replace_accounts(prepared.accounts);
            if let Some((nodes, life)) = prepared.numeric {
                self.legacy_admission.retire();
                self.legacy_admission = life;
                self.local_nodes = nodes;
            }
        }
        self.configuration_reserved = false;
    }
}
