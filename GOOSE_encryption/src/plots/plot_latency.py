import pandas as pd
import matplotlib.pyplot as plt


df = pd.read_csv('../data/mn_data/encryption_latency_log.csv', header=None,
                 names=['algorithm', 'mode', 'latency'], sep=',')
df['algorithm'] = df['algorithm'].str.strip().str.lower()
df['mode'] = df['mode'].str.strip().str.lower()

# keep rows where both are 'none' or both are not 'none'
df = df[((df['algorithm'] == 'none') & (df['mode'] == 'none')) |
        ((df['algorithm'] != 'none') & (df['mode'] != 'none'))]

baseline_filter = (df['algorithm'] == 'none') & (df['mode'] == 'none')
baseline_df = df[baseline_filter]
other_df = df[~baseline_filter]

algorithms = sorted(other_df['algorithm'].unique())

global_modes = sorted(other_df['mode'].unique())

mode_colors = ['lightgreen', 'salmon', 'violet', 'blue', 'red']
mode_to_color = {mode: mode_colors[i % len(mode_colors)] for i, mode in enumerate(global_modes)}

baseline_color = 'grey'

plot_data = []
positions = []
labels = []
modes_for_groups = []  # to store the mode for each box (for color assignment)
pos = 1

if not baseline_df.empty:
    baseline_group = baseline_df['latency']
    plot_data.append(baseline_group.values)
    positions.append(pos)
    labels.append("none\nnone")
    modes_for_groups.append("none")
    pos += 2  # add extra gap after the baseline

for alg in algorithms:
    modes_present = sorted(other_df[other_df['algorithm'] == alg]['mode'].unique())
    for mode in modes_present:
        group = other_df[(other_df['algorithm'] == alg) & (other_df['mode'] == mode)]['latency']
        if not group.empty:
            plot_data.append(group.values)
            positions.append(pos)
            labels.append(f"{alg}\n{mode}")
            modes_for_groups.append(mode)
            pos += 1
    pos += 1  # extra space between different algorithms

fig, ax = plt.subplots(figsize=(12, 8))
bp = ax.boxplot(plot_data, notch=True, patch_artist=True, showfliers=False, positions=positions)

# assign colors
for i, box in enumerate(bp['boxes']):
    mode_val = modes_for_groups[i]
    if mode_val == "none":
        box.set_facecolor(baseline_color)
    else:
        box.set_facecolor(mode_to_color.get(mode_val, 'grey'))


ax.set_xticks(positions)
ax.set_xticklabels(labels, rotation=45, ha='right')

ax.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.7)
ax.minorticks_on()

ax.set_ylabel("Latency (ns)")
plt.tight_layout()
plt.show()


df = pd.read_csv('../data/mn_data/decryption_latency_log.csv',
                 header=None,
                 names=['algorithm', 'mode', 'latency', 'transmission_latency'],
                 sep=',')
df['algorithm'] = df['algorithm'].str.strip().str.lower()
df['mode'] = df['mode'].str.strip().str.lower()

df = df[((df['algorithm'] == 'none') & (df['mode'] == 'none')) |
        ((df['algorithm'] != 'none') & (df['mode'] != 'none'))]

baseline_filter = (df['algorithm'] == 'none') & (df['mode'] == 'none')
baseline_df = df[baseline_filter]
other_df = df[~baseline_filter]

algorithms = sorted(other_df['algorithm'].unique())

global_modes = sorted(other_df['mode'].unique())

mode_to_color = {mode: mode_colors[i % len(mode_colors)] for i, mode in enumerate(global_modes)}

baseline_color = 'grey'

latency_plot_data = []  # data for the latency column
trans_plot_data = []    # data for the transmission_latency column
positions = []          # shared positions for both plots
labels = []             # x-axis labels
modes_for_groups = []   # to store the mode for each group (for color assignment)
pos = 1

if not baseline_df.empty:
    latency_plot_data.append(baseline_df['latency'].values)
    trans_plot_data.append(baseline_df['transmission_latency'].values)
    positions.append(pos)
    labels.append("none\nnone")
    modes_for_groups.append("none")
    pos += 2

for alg in algorithms:
    modes_present = sorted(other_df[other_df['algorithm'] == alg]['mode'].unique())
    for mode in modes_present:
        group = other_df[(other_df['algorithm'] == alg) & (other_df['mode'] == mode)]
        if not group.empty:
            latency_plot_data.append(group['latency'].values)
            trans_plot_data.append(group['transmission_latency'].values)
            positions.append(pos)
            labels.append(f"{alg}\n{mode}")
            modes_for_groups.append(mode)
            pos += 1
    pos += 1  # extra space between different algorithms

# figure for decrypt latency
fig1, ax1 = plt.subplots(figsize=(12, 8))
bp1 = ax1.boxplot(latency_plot_data, notch=True, patch_artist=True,
                  showfliers=False, positions=positions)

for i, box in enumerate(bp1['boxes']):
    mode_val = modes_for_groups[i]
    if mode_val == "none":
        box.set_facecolor(baseline_color)
    else:
        box.set_facecolor(mode_to_color.get(mode_val, 'grey'))

ax1.set_xticks(positions)
ax1.set_xticklabels(labels, rotation=45, ha='right')
ax1.set_title("Decryption Latency")
ax1.set_ylabel("Latency")
ax1.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.7)
ax1.minorticks_on()
plt.tight_layout()
plt.show()

# create 2nd figure for end-to-end latency
fig2, ax2 = plt.subplots(figsize=(12, 8))
bp2 = ax2.boxplot(trans_plot_data, notch=True, patch_artist=True,
                  showfliers=False, positions=positions)

for i, box in enumerate(bp2['boxes']):
    mode_val = modes_for_groups[i]
    if mode_val == "none":
        box.set_facecolor(baseline_color)
    else:
        box.set_facecolor(mode_to_color.get(mode_val, 'grey'))

ax2.set_xticks(positions)
ax2.set_xticklabels(labels, rotation=45, ha='right')
ax2.set_title("Total Transmission Latency")
ax2.set_ylabel("Latency")
ax2.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.7)
ax2.minorticks_on()
plt.tight_layout()
plt.show()