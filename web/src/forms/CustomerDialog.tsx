import { useState } from "react";
import { mutation, type Customer } from "../api";
import { useApp } from "../app/context";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

export default function CustomerDialog({ initial }: { initial: Partial<Customer> }) {
  const { act, closeModal } = useApp();
  const [customerForm, setCustomerForm] = useState(initial);
  const { busy, run } = useBusy();
  const submitCustomer = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (await act(
        () => mutation(customerForm.id ? "/api/customers/" + customerForm.id : "/api/customers", customerForm.id ? "PATCH" : "POST", customerForm),
        customerForm.id ? "客户已保存" : "客户已创建",
      )) closeModal();
    });
  };
  return <Dialog title={customerForm.id ? "编辑客户" : "新建客户"} value={customerForm} initial={initial} busy={busy}>
              <form onSubmit={submitCustomer}>
                <div className="formGrid">
                  <Field label="客户名称 *"><input required maxLength={100} value={customerForm.name || ""} onChange={(e) => setCustomerForm({ ...customerForm, name: e.target.value })} /></Field>
                  <Field label="备注"><input maxLength={1000} value={customerForm.notes || ""} onChange={(e) => setCustomerForm({ ...customerForm, notes: e.target.value })} /></Field>
                </div>
                <SubmitButton busy={busy} label={customerForm.id ? "保存客户" : "创建客户"} />
              </form>
  </Dialog>;
}
