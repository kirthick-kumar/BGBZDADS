import numpy as np
from sklearn.metrics import precision_score, recall_score, roc_auc_score, confusion_matrix


def aggregate_host_errors(edge_errors, host_edge_map, mode="max"):
    host_scores = {}

    for host, errors in host_edge_map.items():
        if mode == "max":
            host_scores[host] = np.max(errors)
        elif mode == "sum":
            host_scores[host] = np.sum(errors)
        else:
            host_scores[host] = np.mean(errors)

    return host_scores


def run_probe_detection(threshold_percentile=90):
    # Load saved results (from notebook / training)
    scores = np.load("host_scores.npy")
    labels = np.load("host_labels.npy")

    threshold = np.percentile(scores, threshold_percentile)
    predictions = (scores > threshold).astype(int)

    precision = precision_score(labels, predictions)
    recall = recall_score(labels, predictions)
    auroc = roc_auc_score(labels, scores)

    tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()
    fpr = fp / (fp + tn + 1e-9)

    detected_hosts = [f"host_{i}" for i, p in enumerate(predictions) if p == 1]

    return {
        "precision": precision,
        "recall": recall,
        "auroc": auroc,
        "fpr": fpr,
        "detected_hosts": detected_hosts[:20],
        "scores": scores,
        "threshold": threshold
    }
