'''
script to plot the charts for the metrics per CWE
'''
import json
import numpy as np
import matplotlib.pyplot as plt
from math import pi


def plot_radar_chart(json_data, output_path):
    # Radar chart dimensions
    labels = ['t1_accuracy', 't1_precision', 't1_recall', 't1_f1',
              't2_accuracy', 't2_precision', 't2_recall', 't2_f1']
    num_vars = len(labels)

    # Calculate angle for each axis
    angles = [n / float(num_vars) * 2 * pi for n in range(num_vars)]
    angles += angles[:1]  # close the circle

    # Create figure and polar subplot
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))

    for entry in json_data:
        cwe = entry['CWE']
        t1 = entry['task1_metrics']
        t2 = entry['task2_metrics'] if entry['task2_metrics'] else {}

        # Extract 8 metric values; use 0 if missing
        values = [
            t1.get('accuracy', 0),
            t1.get('precision', 0),
            t1.get('recall', 0),
            t1.get('f1', 0),
            t2.get('accuracy', 0),
            t2.get('precision', 0),
            t2.get('recall', 0),
            t2.get('f1', 0)
        ]
        values += values[:1]  # close the loop

        ax.plot(angles, values, linewidth=1, linestyle='solid', label=cwe)
        # ax.fill(angles, values, alpha=0.1)

    # Set axis labels
    plt.xticks(angles[:-1], labels, size=10)
    ax.set_rlabel_position(30)
    ax.set_ylim(0, 1)
    plt.title('CWE Metrics Radar Chart (Task1 & Task2)', size=14, y=1.08)
    plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))

    plt.tight_layout()

    # Save with maximum quality settings
    plt.savefig(output_path, format='eps', bbox_inches='tight', pad_inches=0, dpi=1000)
    plt.close()
    print(f"Radar chart saved to {path_to_save_figure}")


if __name__ == "__main__":
    model_name = 'deepseek-coder' # deepseek-chat, deepseek-coder, deepseek-reasoner
    method_name = 'zero-shot' # zero-shot, few-shot
    benchmark_name = 'CWEClassesBench'
    path_to_metrics_per_cwe = f'../results/{model_name}_{benchmark_name}_{method_name}_metrics_per_cwe.json'
    path_to_save_figure = f'../figures/{model_name}_{benchmark_name}_{method_name}_radar_per_cwe.eps'

    # Load the JSON data
    with open(path_to_metrics_per_cwe, 'r') as f:
        json_data = json.load(f)
    
    # paint the radar chart
    plot_radar_chart(json_data, path_to_save_figure)
