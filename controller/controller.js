const ally = require('../adapters/ally');

exports.allyCreateToken = async (req, res, next) => {
    try {
        var array = await ally.compressData(req.body);
        var data = await ally.encryptData(array);
        var response = await ally.post(data);
        var json = await response.json();
        res.send(json);
        res.status(response.status);
    } catch (e) {
        res.status(500).send({
            data: e
        });
    }
};