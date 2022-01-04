# Epilyon server

Backend of the Epilyon app -- Keeping EPITA students organized

## Log format

epilyon.log format is `^\[([^ ]+)] \(([^ ]+)\) \[(\w+)( )?] \[((\w|::)+)] +\| (.+)` for each line (line start is `^\[`),
time group is the 2nd one, severity the 3rd one, category 5th one, message 7th one.

## Launching

### Environment variables

* `EPILYON_DONT_FETCH_EPITAF` - Disables calls to Epitaf's API
* `EPILYON_DONT_SUBSCRIBE` - Prevent Microsoft Graph subscription API from being used (which can't be in localhost)

### Building and running

```
$ cargo run
```

On the first launch, epilyon.toml will have to be filled before launching a second time.

Normal output should look like this:

![Normal ouput](https://cdn.discordapp.com/attachments/447725868140331019/679123908854808586/2020-02-18-011526_1270x446_scrot.png)
