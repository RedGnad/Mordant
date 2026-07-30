"use client";

import { useState, type FormEvent } from "react";

import styles from "./pilot-application-form.module.css";

type SubmissionState =
  | { status: "idle" }
  | { status: "pending" }
  | { status: "error"; message: string }
  | { status: "success"; applicationId: string };

export function PilotApplicationForm({ acceptingApplications }: { readonly acceptingApplications: boolean }) {
  const [submission, setSubmission] = useState<SubmissionState>({ status: "idle" });

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!acceptingApplications || submission.status === "pending") return;

    const form = event.currentTarget;
    const application = Object.fromEntries(new FormData(form));
    setSubmission({ status: "pending" });

    try {
      const response = await fetch("/api/pilot-applications", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(application),
      });
      const body = await response.json() as { error?: string; applicationId?: string };
      if (!response.ok || body.applicationId === undefined) {
        setSubmission({ status: "error", message: body.error ?? "The application could not be sent." });
        return;
      }

      form.reset();
      setSubmission({ status: "success", applicationId: body.applicationId });
    } catch {
      setSubmission({ status: "error", message: "The application channel is unavailable. No data was sent." });
    }
  }

  return (
    <form className={styles.form} onSubmit={submit} data-testid="pilot-application-form">
      <div className={styles.field}>
        <label htmlFor="organization">Organization</label>
        <input id="organization" name="organization" autoComplete="organization" maxLength={120} required />
      </div>

      <div className={styles.field}>
        <label htmlFor="role">Your role</label>
        <select id="role" name="role" defaultValue="" required>
          <option value="" disabled>Select your role</option>
          <option>Credit or operations</option>
          <option>Risk, compliance, or legal</option>
          <option>Product or platform</option>
          <option>Technical or integration</option>
          <option>Executive sponsor</option>
          <option>Other</option>
        </select>
      </div>

      <div className={styles.field}>
        <label htmlFor="portfolioType">Portfolio type</label>
        <select id="portfolioType" name="portfolioType" defaultValue="" required>
          <option value="" disabled>Select a portfolio</option>
          <option>Factoring</option>
          <option>Invoice finance</option>
          <option>Supply-chain finance</option>
          <option>Tokenized receivables</option>
          <option>Private credit</option>
          <option>Other receivables</option>
        </select>
      </div>

      <div className={styles.field}>
        <label htmlFor="approximateVolume">Approximate receivables volume</label>
        <input
          id="approximateVolume"
          name="approximateVolume"
          placeholder="e.g. 20,000 receivables or €250m annually"
          maxLength={80}
          required
        />
      </div>

      <div className={`${styles.field} ${styles.wide}`}>
        <label htmlFor="conflictProcess">How do you manage conflicting claims today?</label>
        <textarea id="conflictProcess" name="conflictProcess" rows={4} maxLength={1_000} required />
      </div>

      <div className={`${styles.field} ${styles.wide}`}>
        <label htmlFor="dataSource">System or data source used</label>
        <textarea id="dataSource" name="dataSource" rows={3} maxLength={500} required />
      </div>

      <div className={`${styles.field} ${styles.wide}`}>
        <label htmlFor="workEmail">Professional email</label>
        <input id="workEmail" name="workEmail" type="email" autoComplete="email" maxLength={254} required />
      </div>

      <div className={styles.trap} aria-hidden="true">
        <label htmlFor="website">Website</label>
        <input id="website" name="website" tabIndex={-1} autoComplete="off" />
      </div>

      <footer className={styles.controls}>
        <p>Do not include borrower names, confidential asset data, wallet keys, or credentials.</p>
        <button type="submit" disabled={!acceptingApplications || submission.status === "pending"}>
          {submission.status === "pending" ? "Sending application…" : "Apply for a shadow pilot"}
        </button>
      </footer>

      <div className={styles.status} aria-live="polite" data-status={submission.status}>
        {!acceptingApplications && submission.status === "idle"
          ? "Application intake is being connected. The questions are available, but no data can be sent yet."
          : submission.status === "error"
            ? submission.message
            : submission.status === "success"
              ? `Application received. Reference ${submission.applicationId}.`
              : ""}
      </div>
    </form>
  );
}
