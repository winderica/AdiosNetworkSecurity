import { makeStyles } from '@material-ui/core/styles';

export const useStyles = makeStyles(({ spacing }) => ({
    container: {
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        alignItems: 'center',
        justifyContent: 'center',
    },
    header: {
        textTransform: 'uppercase',
        letterSpacing: '0.3rem'
    },
}));
