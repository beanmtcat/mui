import { useApp } from "../app/context";
import CertificateDialog from "./CertificateDialog";
import CustomerDialog from "./CustomerDialog";
import ForwardDialog from "./ForwardDialog";
import NodeDialog from "./NodeDialog";
import { BatchDialog, InstallDialog, NodeTraffic, SubscriptionTraffic } from "./Overlays";
import RouteDialog from "./RouteDialog";
import RuleDialog from "./RuleDialog";
import ServerDialog from "./ServerDialog";
import SubscriptionDialog from "./SubscriptionDialog";
import TemplateDialog from "./TemplateDialog";

// Each dialog owns its form, so typing re-renders the dialog and not the page
// behind it. Reopening starts from a fresh form because the object is new.
function EditDialog() {
  const { modal } = useApp();
  if (!modal) return null;
  switch (modal.kind) {
    case "server": return <ServerDialog key={modal.form.id || "new"} initial={modal.form} />;
    case "node": return <NodeDialog key={modal.form.id || "new"} initial={modal.form} templateId={modal.templateId} />;
    case "template": return <TemplateDialog initial={modal.form} />;
    case "certificate": return <CertificateDialog initial={modal.form} />;
    case "rule": return <RuleDialog initial={modal.form} />;
    case "forward": return <ForwardDialog initial={modal.form} targets={modal.targets} />;
    case "route": return <RouteDialog initial={modal.form} />;
    case "subscription": return <SubscriptionDialog initial={modal.form} />;
    case "customer": return <CustomerDialog initial={modal.form} />;
  }
}

export default function Dialogs() {
  return <>
    <InstallDialog />
    <EditDialog />
    <NodeTraffic />
    <SubscriptionTraffic />
    <BatchDialog />
  </>;
}
