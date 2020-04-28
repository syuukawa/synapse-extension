import * as React from 'react';
import Title from '../../Components/Title'
import { Button, TextField } from '@material-ui/core';
import InputAdornment from '@material-ui/core/InputAdornment';
import { makeStyles } from '@material-ui/core/styles';
import { Formik, Form } from "formik";
import * as Yup from "yup";
import { MESSAGE_TYPE } from '../../../utils/constants'
import { useHistory } from "react-router-dom";
import { AppContext } from '../../App';
import Radio from '@material-ui/core/Radio';
import RadioGroup from '@material-ui/core/RadioGroup';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import FormControl from '@material-ui/core/FormControl';

const useStyles = makeStyles({
  container: {
    margin: 30,
  },
  button: {

  },
  textField: {

  }
});

interface AppProps { }

interface AppState { }

export default function ImportPrivateKey(props: AppProps, state: AppState) {
  const [success, setSuccess] = React.useState(false)
  const history = useHistory();
  const { network } = React.useContext(AppContext);
  const [isHidePrivate, setIsHidePrivate] = React.useState(false);
  const [value, setValue] = React.useState("1");

  React.useEffect(() => {
    chrome.runtime.onMessage.addListener((msg, sender, sendResp) => {
      if (msg.messageType === MESSAGE_TYPE.IMPORT_PRIVATE_KEY_OK || msg.messageType === MESSAGE_TYPE.IMPORT_KEYSTORE_OK) {
        history.push('/address')
      }
    })
  }, [])

  const onSubmit = async (values) => {
    if (isHidePrivate) {
      chrome.runtime.sendMessage({ ...values, messageType: MESSAGE_TYPE.IMPORT_PRIVATE_KEY })
      setSuccess(true)
    } else {
      chrome.runtime.sendMessage({ ...values, messageType: MESSAGE_TYPE.IMPORT_KEYSTORE })
      setSuccess(true)
    }
  }

  const handleRadioChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setValue((event.target as HTMLInputElement).value);
    if (value === "1") {
      setIsHidePrivate(true);
    } else {
      setIsHidePrivate(false);
    }
  };

  let successNode = null
  if (success) successNode = <div className="success">Successfully</div>

  const classes = useStyles();

  const innerForm = props => {
    const classes = useStyles();
    const {
      values,
      touched,
      errors,
      dirty,
      isSubmitting,
      handleChange,
      handleBlur,
      handleSubmit,
      handleReset
    } = props;


    const privateKeyFrom =
      <Form className="form-mnemonic" id="form-mnemonic" onSubmit={handleSubmit}>
        <TextField
          label="PrivateKey"
          name="privatekey"
          type="text"
          placeholder="私钥"
          fullWidth
          InputProps={{
            startAdornment: <InputAdornment position="start">0x</InputAdornment>,
          }}
          className={classes.textField}
          value={values.privatekey}
          onChange={handleChange}
          onBlur={handleBlur}
          error={!!errors.password}
          // helperText={(errors.confirmPassword && touched.confirmPassword) && errors.confirmPassword}
          margin="normal"
          variant="outlined"
          data-testid=""
        />
        <TextField
          label="Password"
          name="password"
          type="password"
          placeholder="原密码"
          fullWidth
          className={classes.textField}
          value={values.password}
          onChange={handleChange}
          onBlur={handleBlur}
          error={!!errors.password}
          // helperText={(errors.confirmPassword && touched.confirmPassword) && errors.confirmPassword}
          margin="normal"
          variant="outlined"
          data-testid=""
        />
        {isSubmitting && <div id="submitting">Submitting</div>}
        <Button
          type="submit"
          variant="contained"
          disabled={isSubmitting}
          color="primary"
          className={classes.button}
          data-testid="import-privateKey-submit"
        >
          Import
      </Button>
      </Form>

    const keystoreFrom =
      <Form className="form-keystore" id="form-keystore" onSubmit={handleSubmit}>
        <TextField
          label="keystore"
          name="keystore"
          multiline
          rows="4"
          fullWidth
          className={classes.textField}
          value={values.keystore}
          onChange={handleChange}
          onBlur={handleBlur}
          error={!!errors.keystore}
          helperText={(errors.keystore && touched.keystore) && errors.keystore}
          margin="normal"
          variant="outlined"
          data-testid="field-keystore"
        />
        {/* <Popper id={'simple-popper'} open={true} >
              <div className={classesPopper.paper}>Invalid mnemonic</div>
            </Popper> */}
        <TextField
          label="keystore password"
          name="keystorePassword"
          type="password"
          fullWidth
          className={classes.textField}
          value={values.keystorePassword}
          onChange={handleChange}
          onBlur={handleBlur}
          error={!!errors.keystorePassword}
          helperText={(errors.keystorePassword && touched.keystorePassword) && errors.keystorePassword}
          margin="normal"
          variant="outlined"
          data-testid="field-keystore-password"
        />
        <TextField
          label="synapse password"
          name="synapsePassword"
          type="password"
          fullWidth
          className={classes.textField}
          value={values.synapsePassword}
          onChange={handleChange}
          onBlur={handleBlur}
          error={!!errors.synapsePassword}
          helperText={(errors.synapsePassword && touched.synapsePassword) && errors.synapsePassword}
          margin="normal"
          variant="outlined"
          data-testid="field-synapse-password"
        />
        {isSubmitting && <div id="submitting">Submitting</div>}
        <Button
          type="submit"
          id="import-keystore-submit-button"
          variant="contained"
          disabled={isSubmitting}
          color="primary"
          className={classes.button}
          data-testid="import-keystore-submit"
        >
          Import
        </Button>
      </Form>

    return (
      <FormControl component="fieldset" >
        <div className={classes.container}>
          <div className="privateKey" data-testid="privateKey" hidden={isHidePrivate}>
            {privateKeyFrom}
          </div>
          <div className="json-keystore" data-testid="json-keystore" hidden={!isHidePrivate}>
            {/* <span className="">JSON/Keystore  </span> */}
            {keystoreFrom}
          </div>
        </div>
      </FormControl>
    );
  }

  type validateObjType = {
    password?: Yup.StringSchema<string>;
    privatekey?: Yup.StringSchema<string>;
    keystore?: Yup.StringSchema<string>;
    keystorePassword?: Yup.StringSchema<string>;
    synapsePassword?: Yup.StringSchema<string>;
  }

  const validateObj: validateObjType = !isHidePrivate ? {
    password: Yup.string().required("Required").min(6),
    privatekey: Yup.string().required("Required").length(64).matches(/[0-9a-fA-F]+/),
  } : {
    keystore: Yup.string().required("Required"),
    keystorePassword: Yup.string().required("Required").min(6),
    synapsePassword: Yup.string().required("Required").min(6),
  }

  return (
    <div className={classes.container}>
      {successNode}
      <RadioGroup row value={value} onChange={handleRadioChange} >
        <FormControlLabel value="1" labelPlacement="bottom" control={<Radio />} label="PrivateKey" />
        <FormControlLabel value="2" labelPlacement="bottom" control={<Radio />} label="Keystore" />
      </RadioGroup>

      <Formik
        initialValues={{ password: "", privatekey: "", keystore: "", keystorePassword: "", synapsePassword: "", }}

        onSubmit={onSubmit}
        validationSchema={Yup.object().shape(validateObj)}
      >
        {innerForm}
      </Formik>
    </div>
  )
}
