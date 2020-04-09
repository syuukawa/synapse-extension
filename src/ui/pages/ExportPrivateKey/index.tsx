import * as React from 'react';
// import './Popup.scss';
import Title from '../../Components/Title'
import { Button, TextField } from '@material-ui/core';
// import { makeStyles } from '@material-ui/core/styles';
import { Formik, Form } from "formik";
import * as Yup from "yup";
import { MESSAGE_TYPE } from '../../../utils/constants'
import { useHistory } from "react-router-dom";
import { makeStyles, Theme, createStyles } from '@material-ui/core/styles';

const useStylesPopper = makeStyles((theme: Theme) =>
  createStyles({
    paper: {
      border: '1px solid',
      padding: theme.spacing(1),
      backgroundColor: theme.palette.background.paper,
    },
  }),
);

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

export const innerForm = props => {
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

  return (
    <Form className="export-private-key" id="export-private-key" onSubmit={handleSubmit}>
      
      <TextField
        label="Password"
        name="password"
        type="password"
        fullWidth
        className={classes.textField}
        value={values.password}
        onChange={handleChange}
        onBlur={handleBlur}
        error={!!errors.password}
        helperText={(errors.password && touched.password) && errors.password}
        margin="normal"
        variant="outlined"
        data-testid="field-password"
      />

      {isSubmitting && <div id="submitting">Submitting</div>}
      <Button
        type="submit"
        id="submit-button"
        disabled={isSubmitting}
        color="primary"
        className={classes.button}
        data-testid="submit-button"
      >
        Confirm
      </Button>
    </Form>
  );
}

export default function (props: AppProps, state: AppState) {

  const [success, setSuccess] = React.useState(false)
  const [vaildate, setValidate] = React.useState(true)
  const history = useHistory();

  const onSubmit = async(values) => {
    await new Promise(resolve => setTimeout(resolve, 500));
    //background.ts check the password
    chrome.runtime.sendMessage({ ...values, messageType: MESSAGE_TYPE.EXPORT_PRIVATE_KEY_CHECK })
    console.log("export-private-key =>",values)
  }

  React.useEffect(() => {
    chrome.runtime.onMessage.addListener(function(
      message,sender,sendResponse) {

      if (message === MESSAGE_TYPE.IS_NOT_VALIDATE_MNEMONIC) {

        console.log("index.tsx => message",message);
        setValidate(false);//false验证未通过
        return;

      }
    });
  }, []);


  let successNode = null
  if (success) successNode = <div className="success">Successfully</div>
  if (!vaildate) successNode = <div className="success">Invalid passwrod</div>
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <Title title='Export Private Key' testId="export-private-key-title" />
        {successNode}
      <Formik
        initialValues={{ password: "" }}
        onSubmit={onSubmit}
        validationSchema={Yup.object().shape({
          password: Yup.string()
            .min(6)
            .required("Required")
        })}
      >
        {innerForm}
      </Formik>
    </div>
  )
}