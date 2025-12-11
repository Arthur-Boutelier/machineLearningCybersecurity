const LABELS = ["Benign", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "PortScan", "SSH-Patator", "Web Attack/Brute Force", "Web Attack/XSS"]
const FEATURES_CONFIG = [
{name: 'DestinationPort', type: 'int', default: 80},
{name: 'FlowDuration', type: 'int', default: 134105},
{name: 'TotalFwdPackets', type: 'int', default: 6},
{name: 'TotalBackwardPackets', type: 'int', default: 7},
{name: 'TotalLengthOfFwdPackets', type: 'int', default: 313},
{name: 'TotalLengthOfBwdPackets', type: 'int', default: 11601},
{name: 'FwdPacketLengthMax', type: 'int', default: 154},
{name: 'FwdPacketLengthMin', type: 'int', default: 0},
{name: 'FwdPacketLengthMean', type: 'float', default: 52.1666667},
{name: 'FwdPacketLengthStd', type: 'float', default: 68.397635},
{name: 'BwdPacketLengthMax', type: 'int', default: 4640},
{name: 'BwdPacketLengthMin', type: 'int', default: 0},
{name: 'BwdPacketLengthMean', type: 'float', default: 1657.285714},
{name: 'BwdPacketLengthStd', type: 'float', default: 2043.901844},
{name: 'FlowBytesPerS', type: 'float', default: 88835.498},
{name: 'FlowPacketsPerS', type: 'float', default: 96.938},
{name: 'FlowIatMean', type: 'float', default: 10315.76923},
{name: 'FlowIatStd', type: 'float', default: 34966.723},
{name: 'FlowIatMax', type: 'int', default: 125197},
{name: 'FlowIatMin', type: 'int', default: 1},
{name: 'FwdIatTotal', type: 'int', default: 134105},
{name: 'FwdIatMean', type: 'float', default: 26821.0},
{name: 'FwdIatStd', type: 'float', default: 53513.682},
{name: 'FwdIatMax', type: 'int', default: 125197},
{name: 'FwdIatMin', type: 'int', default: 1},
{name: 'BwdIatTotal', type: 'int', default: 134105},
{name: 'BwdIatMean', type: 'int', default: 6500},
{name: 'BwdIatStd', type: 'float', default: 43577.854},
{name: 'BwdIatMax', type: 'int', default: 125197},
{name: 'BwdIatMin', type: 'int', default: 1},
{name: 'FwdPshFlags', type: 'int', default: 0},
{name: 'BwdPshFlags', type: 'int', default: 0},
{name: 'FwdUrgFlags', type: 'int', default: 0},
{name: 'BwdUrgFlags', type: 'int', default: 0},
{name: 'FwdHeaderLength', type: 'int', default: 124},
{name: 'BwdHeaderLength', type: 'int', default: 152},
{name: 'FwdPacketsPerS', type: 'float', default: 44.741},
{name: 'BwdPacketsPerS', type: 'float', default: 52.197},
{name: 'MinPacketLength', type: 'int', default: 0},
{name: 'MaxPacketLength', type: 'int', default: 4640},
{name: 'PacketLengthMean', type: 'float', default: 916.461538},
{name: 'PacketLengthStd', type: 'float', default: 1633.20888},
{name: 'PacketLengthVariance', type: 'float', default: 2667468.96},
{name: 'FinFlagCount', type: 'int', default: 1},
{name: 'SynFlagCount', type: 'int', default: 0},
{name: 'RstFlagCount', type: 'int', default: 0},
{name: 'PshFlagCount', type: 'int', default: 1},
{name: 'AckFlagCount', type: 'int', default: 1},
{name: 'UrgFlagCount', type: 'int', default: 0},
{name: 'CweFlagCount', type: 'int', default: 0},
{name: 'EceFlagCount', type: 'int', default: 0},
{name: 'DownPerupRatio', type: 'int', default: 1},
{name: 'AveragePacketSize', type: 'float', default: 986.75},
{name: 'AvgFwdSegmentSize', type: 'float', default: 52.1666667},
{name: 'AvgBwdSegmentSize', type: 'float', default: 1657.285714},
{name: 'FwdHeaderLength1', type: 'int', default: 124},
{name: 'FwdAvgBytesPerBulk', type: 'int', default: 0},
{name: 'FwdAvgPacketsPerBulk', type: 'int', default: 0},
{name: 'FwdAvgBulkRate', type: 'int', default: 0},
{name: 'BwdAvgBytesPerBulk', type: 'int', default: 0},
{name: 'BwdAvgPacketsPerBulk', type: 'int', default: 0},
{name: 'BwdAvgBulkRate', type: 'int', default: 0},
{name: 'SubflowFwdPackets', type: 'int', default: 6},
{name: 'SubflowFwdBytes', type: 'int', default: 313},
{name: 'SubflowBwdPackets', type: 'int', default: 7},
{name: 'SubflowBwdBytes', type: 'int', default: 11601},
{name: 'Init_win_bytes_forward', type: 'int', default: 29200},
{name: 'Init_win_bytes_backward', type: 'int', default: 268},
{name: 'Act_data_pkt_fwd', type: 'int', default: 4},
{name: 'Min_seg_size_forward', type: 'int', default: 20},
{name: 'ActiveMean', type: 'float', default: 0.0},
{name: 'ActiveStd', type: 'float', default: 0.0},
{name: 'ActiveMin', type: 'int', default: 0},
{name: 'ActiveMax', type: 'int', default: 0},
{name: 'IdleMean', type: 'float', default: 0.0},
{name: 'IdleStd', type: 'float', default: 0.0},
{name: 'IdleMax', type: 'int', default: 0},
{name: 'IdleMin', type: 'int', default: 0},
{name: 'SourceFile', type: 'int', default: 1}
];

const MODEL_KEYS = ["knn_smote", "rand_forest_smote", "hard_voting"];
const API_BASE_URL = "/predict/";


function generateForm() {
    const container = document.getElementById('featuresContainer');
    const modelSelect = document.getElementById('modelSelect');

    MODEL_KEYS.forEach(key => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = key.charAt(0).toUpperCase() + key.slice(1);
        modelSelect.appendChild(option);
    });

    FEATURES_CONFIG.forEach(feature => {
        const div = document.createElement('div');
        div.className = 'form-group';

        const label = document.createElement('label');
        label.setAttribute('for', feature.name);
        label.textContent = feature.name;

        const input = document.createElement('input');
        input.type = 'text';
        input.id = feature.name;
        input.name = feature.name;
        input.value = feature.default;
        input.required = true;
        input.dataset.type = feature.type;

        div.appendChild(label);
        div.appendChild(input);
        container.appendChild(div);
    });
}

async function handleSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const output = document.getElementById('predictionOutput');
    const selectedModel = document.getElementById('modelSelect').value;

    output.textContent = "Loading...";

    const inputData = {};
    let dataIsValid = true;
    FEATURES_CONFIG.forEach(feature => {
        const inputElement = form.elements[feature.name];
        let value = inputElement.value.trim();

        if (feature.type === 'int') {
            const intValue = parseInt(value);
            if (isNaN(intValue)) {
                alert(`${feature.name} must be an integer`);
                dataIsValid = false;
            }
            inputData[feature.name] = intValue;
        } else if (feature.type === 'float') {
            value = value.replace(',', '.');
            const floatValue = parseFloat(value);
            if (isNaN(floatValue)) {
                alert(`${feature.name} must be a float`);
                dataIsValid = false;
            }
            inputData[feature.name] = floatValue;
        }
    });

    if (!dataIsValid) {
        output.textContent = "Data not correct";
        return;
    }

    const payload = {
        data: [inputData]
    };

    try {
        console.log(payload)
        const response = await fetch(API_BASE_URL + selectedModel, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (response.ok) {
            output.innerHTML = `
                <p><strong>Model used :</strong> ${selectedModel}</p>
                <p><strong>Prediction :</strong> ${LABELS[result.predictions[0]]}</p>
            `;
        } else {
            output.innerHTML = `
                <p style="color: red;">Error ${response.status} : ${response.statusText}</p>
                <p>Server: ${JSON.stringify(result.detail || result)}</p>
            `;
        }

    } catch (error) {
        output.innerHTML = `<p style="color: red;">Api error: ${error.message}</p>`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    generateForm();
    document.getElementById('predictionForm').addEventListener('submit', handleSubmit);
});
